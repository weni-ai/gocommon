package storage

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
)

// MaxPresignExpiration is the longest expiration SigV4 allows for a presigned URL
const MaxPresignExpiration = 7 * 24 * time.Hour

const awsHostSuffix = ".amazonaws.com"

var awsRegionRegex = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

var knownAWSRegions = loadKnownAWSRegions()

func loadKnownAWSRegions() map[string]bool {
	regions := make(map[string]bool)
	for _, partition := range endpoints.DefaultPartitions() {
		for id := range partition.Regions() {
			regions[id] = true
		}
	}
	return regions
}

// ParseS3URL extracts bucket, key and (optional) region from an S3 object URL. It supports virtual-hosted
// URLs (bucket.s3.amazonaws.com, bucket.s3.<region>.amazonaws.com, bucket.s3-<region>.amazonaws.com) and
// path-style URLs (s3[.-]<region>.amazonaws.com/<bucket>/<key>). Any query string is ignored.
func ParseS3URL(rawURL string) (bucket, key, region string, ok bool) {
	u, ok := parseHTTPURL(rawURL)
	if !ok {
		return "", "", "", false
	}

	host := strings.ToLower(u.Hostname())
	if !strings.HasSuffix(host, awsHostSuffix) {
		return "", "", "", false
	}
	prefix := strings.TrimSuffix(host, awsHostSuffix)

	if region, ok = parseS3HostRegion(prefix); ok {
		if bucket, key, ok = splitPathStyle(u.Path); !ok {
			return "", "", "", false
		}
		return bucket, key, region, true
	}

	sep := strings.LastIndex(prefix, ".s3")
	if sep <= 0 {
		return "", "", "", false
	}
	region, ok = parseS3HostRegion(prefix[sep+1:])
	if !ok {
		return "", "", "", false
	}

	key = strings.TrimPrefix(u.Path, "/")
	if key == "" {
		return "", "", "", false
	}
	return prefix[:sep], key, region, true
}

// parseS3HostRegion parses an S3 host label (s3, s3.<region> or s3-<region>) returning the region if any
func parseS3HostRegion(label string) (string, bool) {
	if label == "s3" {
		return "", true
	}
	if !strings.HasPrefix(label, "s3.") && !strings.HasPrefix(label, "s3-") {
		return "", false
	}
	region := label[3:]
	return region, awsRegionRegex.MatchString(region)
}

func splitPathStyle(path string) (bucket, key string, ok bool) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func parseHTTPURL(rawURL string) (*url.URL, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, false
	}
	return u, true
}

// S3URLSigner presigns GET URLs for objects in a set of allowed buckets. All buckets are signed with the
// same credentials, resolved like NewS3Client does (static keys if set, otherwise the default chain).
//
// When those credentials are temporary (e.g. IRSA), a presigned URL stops working when the session token
// used to sign it expires, regardless of the requested expiration.
type S3URLSigner struct {
	session        *session.Session
	opts           *S3Options
	endpointHost   string
	allowedBuckets map[string]bool

	clientsMutex sync.Mutex
	clients      map[s3SignerClientKey]*s3.S3
}

type s3SignerClientKey struct {
	endpoint string
	region   string
}

// NewS3URLSigner creates a new signer for objects in the given buckets
func NewS3URLSigner(opts *S3Options, allowedBuckets []string) (*S3URLSigner, error) {
	sess, err := newS3Session(opts)
	if err != nil {
		return nil, err
	}

	endpointHost := ""
	if opts.Endpoint != "" {
		endpoint := opts.Endpoint
		if !strings.Contains(endpoint, "://") {
			endpoint = "https://" + endpoint
		}
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid S3 endpoint %s", opts.Endpoint)
		}
		endpointHost = strings.ToLower(u.Host)
	}

	allowed := make(map[string]bool, len(allowedBuckets))
	for _, b := range allowedBuckets {
		if b = strings.TrimSpace(b); b != "" {
			allowed[b] = true
		}
	}

	return &S3URLSigner{
		session:        sess,
		opts:           opts,
		endpointHost:   endpointHost,
		allowedBuckets: allowed,
		clients:        make(map[s3SignerClientKey]*s3.S3),
	}, nil
}

// Sign returns a presigned GET URL; signed=false (and the input URL) when the URL
// is not an S3 URL of an allowed bucket in a known region
func (s *S3URLSigner) Sign(rawURL string, expiration time.Duration) (string, bool, error) {
	if expiration <= 0 || expiration > MaxPresignExpiration {
		return "", false, errors.Errorf("presign expiration must be greater than 0 and at most %s, got %s", MaxPresignExpiration, expiration)
	}

	bucket, key, clientKey, ok := s.parse(rawURL)
	if !ok || !s.allowedBuckets[bucket] {
		return rawURL, false, nil
	}

	req, _ := s.client(clientKey).GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	signedURL, err := req.Presign(expiration)
	if err != nil {
		return "", false, errors.Wrapf(err, "error presigning S3 URL")
	}
	return signedURL, true, nil
}

// parse resolves the bucket and key of the URL, and which client should sign it. AWS hosted URLs are signed
// against AWS for their region, and path-style URLs on the configured endpoint host against that endpoint.
// Regions come from the URL and each gets a cached client, so only the configured region and regions known
// to the SDK are accepted.
func (s *S3URLSigner) parse(rawURL string) (bucket, key string, clientKey s3SignerClientKey, ok bool) {
	if bucket, key, region, ok := ParseS3URL(rawURL); ok {
		if region == "" {
			region = s.opts.Region
		}
		if region != s.opts.Region && !knownAWSRegions[region] {
			return "", "", s3SignerClientKey{}, false
		}
		return bucket, key, s3SignerClientKey{region: region}, true
	}

	if s.endpointHost == "" {
		return "", "", s3SignerClientKey{}, false
	}
	u, ok := parseHTTPURL(rawURL)
	if !ok || strings.ToLower(u.Host) != s.endpointHost {
		return "", "", s3SignerClientKey{}, false
	}
	bucket, key, ok = splitPathStyle(u.Path)
	return bucket, key, s3SignerClientKey{endpoint: s.opts.Endpoint, region: s.opts.Region}, ok
}

func (s *S3URLSigner) client(key s3SignerClientKey) *s3.S3 {
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	client, ok := s.clients[key]
	if !ok {
		client = s3.New(s.session, s3ClientConfig(s.opts, key.endpoint, key.region))
		s.clients[key] = client
	}
	return client
}
