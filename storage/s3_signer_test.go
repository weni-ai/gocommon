package storage_test

import (
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nyaruka/gocommon/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseS3URL(t *testing.T) {
	tcs := []struct {
		url    string
		bucket string
		key    string
		region string
		ok     bool
	}{
		// virtual-hosted
		{"https://mybucket.s3.amazonaws.com/media/foo.jpg", "mybucket", "media/foo.jpg", "", true},
		{"https://mybucket.s3.sa-east-1.amazonaws.com/media/foo.jpg", "mybucket", "media/foo.jpg", "sa-east-1", true},
		{"https://mybucket.s3-sa-east-1.amazonaws.com/media/foo.jpg", "mybucket", "media/foo.jpg", "sa-east-1", true},
		{"http://mybucket.s3.us-gov-west-1.amazonaws.com/foo.jpg", "mybucket", "foo.jpg", "us-gov-west-1", true},
		{"https://MyBucket.S3.SA-EAST-1.amazonaws.com/Foo.jpg", "mybucket", "Foo.jpg", "sa-east-1", true},
		{"https://my.dotted.bucket.s3.sa-east-1.amazonaws.com/foo.jpg", "my.dotted.bucket", "foo.jpg", "sa-east-1", true},
		{"https://my.s3.bucket.s3-sa-east-1.amazonaws.com/foo.jpg", "my.s3.bucket", "foo.jpg", "sa-east-1", true},
		{"https://my.dotted.bucket.s3.amazonaws.com/foo.jpg", "my.dotted.bucket", "foo.jpg", "", true},

		// path-style
		{"https://s3.amazonaws.com/mybucket/media/foo.jpg", "mybucket", "media/foo.jpg", "", true},
		{"https://s3.sa-east-1.amazonaws.com/mybucket/media/foo.jpg", "mybucket", "media/foo.jpg", "sa-east-1", true},
		{"https://s3-sa-east-1.amazonaws.com/my.dotted.bucket/foo.jpg", "my.dotted.bucket", "foo.jpg", "sa-east-1", true},

		// query strings are ignored and keys are unescaped
		{"https://mybucket.s3.sa-east-1.amazonaws.com/media/foo.jpg?X-Amz-Signature=abc&X-Amz-Expires=60", "mybucket", "media/foo.jpg", "sa-east-1", true},
		{"https://s3.sa-east-1.amazonaws.com/mybucket/foo.jpg?X-Amz-Signature=abc", "mybucket", "foo.jpg", "sa-east-1", true},
		{"https://mybucket.s3.sa-east-1.amazonaws.com/media/my%20file%2B1.jpg", "mybucket", "media/my file+1.jpg", "sa-east-1", true},

		// not S3 object URLs
		{"", "", "", "", false},
		{"not a url", "", "", "", false},
		{"ftp://mybucket.s3.amazonaws.com/foo.jpg", "", "", "", false},
		{"https://example.com/foo.jpg", "", "", "", false},
		{"https://mybucket.s3.sa-east-1.amazonaws.com.evil.com/foo.jpg", "", "", "", false},
		{"https://ec2.sa-east-1.amazonaws.com/foo.jpg", "", "", "", false},
		{"https://mybucket.s3-accelerate.amazonaws.com/foo.jpg", "", "", "", false},
		{"https://mybucket.s3-website-sa-east-1.amazonaws.com/foo.jpg", "", "", "", false},
		{"https://mybucket.s3x.amazonaws.com/foo.jpg", "", "", "", false},
		{"https://.s3.sa-east-1.amazonaws.com/foo.jpg", "", "", "", false},
		{"https://mybucket.s3.sa-east-1.amazonaws.com/", "", "", "", false},
		{"https://mybucket.s3.sa-east-1.amazonaws.com", "", "", "", false},
		{"https://s3.sa-east-1.amazonaws.com/mybucket", "", "", "", false},
		{"https://s3.sa-east-1.amazonaws.com/mybucket/", "", "", "", false},
		{"https://s3.sa-east-1.amazonaws.com/", "", "", "", false},
	}

	for _, tc := range tcs {
		bucket, key, region, ok := storage.ParseS3URL(tc.url)
		assert.Equal(t, tc.ok, ok, "ok mismatch for %s", tc.url)
		assert.Equal(t, tc.bucket, bucket, "bucket mismatch for %s", tc.url)
		assert.Equal(t, tc.key, key, "key mismatch for %s", tc.url)
		assert.Equal(t, tc.region, region, "region mismatch for %s", tc.url)
	}
}

func TestS3URLSignerSign(t *testing.T) {
	signer, err := storage.NewS3URLSigner(&storage.S3Options{
		AWSAccessKeyID:     "AKIDTEST",
		AWSSecretAccessKey: "secret",
		Region:             "sa-east-1",
	}, []string{"media-bucket", " attachments.bucket ", ""})
	require.NoError(t, err)

	tcs := []struct {
		url          string
		signed       bool
		host         string
		path         string
		signedRegion string
	}{
		{"https://media-bucket.s3.sa-east-1.amazonaws.com/media/foo.jpg", true, "media-bucket.s3.sa-east-1.amazonaws.com", "/media/foo.jpg", "sa-east-1"},
		{"https://media-bucket.s3.us-east-1.amazonaws.com/media/foo.jpg", true, "media-bucket.s3.amazonaws.com", "/media/foo.jpg", "us-east-1"},
		{"https://media-bucket.s3.amazonaws.com/media/foo.jpg", true, "media-bucket.s3.sa-east-1.amazonaws.com", "/media/foo.jpg", "sa-east-1"},
		{"https://s3.sa-east-1.amazonaws.com/media-bucket/media/foo.jpg", true, "media-bucket.s3.sa-east-1.amazonaws.com", "/media/foo.jpg", "sa-east-1"},
		{"https://media-bucket.s3.sa-east-1.amazonaws.com/media/foo.jpg?X-Amz-Signature=old", true, "media-bucket.s3.sa-east-1.amazonaws.com", "/media/foo.jpg", "sa-east-1"},
		{"https://media-bucket.s3.sa-east-1.amazonaws.com/media/my%20file.jpg", true, "media-bucket.s3.sa-east-1.amazonaws.com", "/media/my file.jpg", "sa-east-1"},
		{"https://attachments.bucket.s3.sa-east-1.amazonaws.com/foo.jpg", true, "s3.sa-east-1.amazonaws.com", "/attachments.bucket/foo.jpg", "sa-east-1"},

		{"https://other-bucket.s3.sa-east-1.amazonaws.com/media/foo.jpg", false, "", "", ""},
		{"https://example.com/media/foo.jpg", false, "", "", ""},
		{"https://media-bucket.example.com/media/foo.jpg", false, "", "", ""},
	}

	for _, tc := range tcs {
		signedURL, signed, err := signer.Sign(tc.url, time.Hour)
		require.NoError(t, err, "unexpected error for %s", tc.url)
		assert.Equal(t, tc.signed, signed, "signed mismatch for %s", tc.url)

		if !tc.signed {
			assert.Equal(t, tc.url, signedURL, "unsigned URL should be returned as is for %s", tc.url)
			continue
		}

		u, err := url.Parse(signedURL)
		require.NoError(t, err)
		assert.Equal(t, "https", u.Scheme, "scheme mismatch for %s", tc.url)
		assert.Equal(t, tc.host, u.Host, "host mismatch for %s", tc.url)
		assert.Equal(t, tc.path, u.Path, "path mismatch for %s", tc.url)

		query := u.Query()
		assert.Equal(t, "3600", query.Get("X-Amz-Expires"), "expires mismatch for %s", tc.url)
		assert.NotEmpty(t, query.Get("X-Amz-Signature"), "missing signature for %s", tc.url)
		assert.NotEqual(t, "old", query.Get("X-Amz-Signature"), "old signature kept for %s", tc.url)
		credential := strings.Split(query.Get("X-Amz-Credential"), "/")
		require.Len(t, credential, 5, "credential mismatch for %s", tc.url)
		assert.Equal(t, "AKIDTEST", credential[0])
		assert.Equal(t, tc.signedRegion, credential[2], "credential region mismatch for %s", tc.url)
		assert.Equal(t, "s3", credential[3])
	}
}

func TestS3URLSignerConcurrentSign(t *testing.T) {
	signer, err := storage.NewS3URLSigner(&storage.S3Options{
		AWSAccessKeyID:     "AKIDTEST",
		AWSSecretAccessKey: "secret",
		Region:             "sa-east-1",
	}, []string{"media-bucket"})
	require.NoError(t, err)

	wg := &sync.WaitGroup{}
	for i := 0; i < 20; i++ {
		region := []string{"sa-east-1", "us-east-1", "eu-west-1"}[i%3]
		wg.Add(1)
		go func() {
			defer wg.Done()
			signedURL, signed, err := signer.Sign("https://media-bucket.s3."+region+".amazonaws.com/foo.jpg", time.Hour)
			assert.NoError(t, err)
			assert.True(t, signed)
			assert.Contains(t, signedURL, "%2F"+region+"%2Fs3%2F")
		}()
	}
	wg.Wait()
}

func TestS3URLSignerExpiration(t *testing.T) {
	signer, err := storage.NewS3URLSigner(&storage.S3Options{
		AWSAccessKeyID:     "AKIDTEST",
		AWSSecretAccessKey: "secret",
		Region:             "sa-east-1",
	}, []string{"media-bucket"})
	require.NoError(t, err)

	rawURL := "https://media-bucket.s3.sa-east-1.amazonaws.com/media/foo.jpg"

	signedURL, signed, err := signer.Sign(rawURL, storage.MaxPresignExpiration)
	assert.NoError(t, err)
	assert.True(t, signed)
	assert.Contains(t, signedURL, "X-Amz-Expires=604800")

	for _, expiration := range []time.Duration{0, -time.Second, storage.MaxPresignExpiration + time.Second} {
		_, signed, err = signer.Sign(rawURL, expiration)
		assert.EqualError(t, err, "presign expiration must be greater than 0 and at most 168h0m0s, got "+expiration.String())
		assert.False(t, signed)
	}

	// expiration is validated even for URLs we wouldn't sign
	_, _, err = signer.Sign("https://example.com/foo.jpg", 0)
	assert.Error(t, err)
}

func TestS3URLSignerCustomEndpoint(t *testing.T) {
	signer, err := storage.NewS3URLSigner(&storage.S3Options{
		AWSAccessKeyID:     "AKIDTEST",
		AWSSecretAccessKey: "secret",
		Region:             "us-east-1",
		Endpoint:           "http://localhost:9000",
		DisableSSL:         true,
		ForcePathStyle:     true,
	}, []string{"media-bucket"})
	require.NoError(t, err)

	signedURL, signed, err := signer.Sign("http://localhost:9000/media-bucket/media/foo.jpg?X-Amz-Signature=old", time.Minute)
	require.NoError(t, err)
	assert.True(t, signed)

	u, err := url.Parse(signedURL)
	require.NoError(t, err)
	assert.Equal(t, "http", u.Scheme)
	assert.Equal(t, "localhost:9000", u.Host)
	assert.Equal(t, "/media-bucket/media/foo.jpg", u.Path)
	assert.Equal(t, "60", u.Query().Get("X-Amz-Expires"))
	assert.Contains(t, u.Query().Get("X-Amz-Credential"), "/us-east-1/s3/aws4_request")

	// other buckets and hosts on the endpoint aren't signed
	for _, rawURL := range []string{
		"http://localhost:9000/other-bucket/media/foo.jpg",
		"http://localhost:9001/media-bucket/media/foo.jpg",
		"http://localhost:9000/media-bucket",
	} {
		signedURL, signed, err = signer.Sign(rawURL, time.Minute)
		assert.NoError(t, err)
		assert.False(t, signed, "should not sign %s", rawURL)
		assert.Equal(t, rawURL, signedURL)
	}

	// AWS hosted URLs are still signed against AWS for their region, honoring the path-style and SSL options
	signedURL, signed, err = signer.Sign("https://media-bucket.s3.sa-east-1.amazonaws.com/media/foo.jpg", time.Minute)
	require.NoError(t, err)
	assert.True(t, signed)
	assert.True(t, strings.HasPrefix(signedURL, "http://s3.sa-east-1.amazonaws.com/media-bucket/media/foo.jpg?"), signedURL)
	assert.Contains(t, signedURL, "sa-east-1%2Fs3%2Faws4_request")

	// an endpoint without a scheme still matches by host
	signer, err = storage.NewS3URLSigner(&storage.S3Options{
		AWSAccessKeyID:     "AKIDTEST",
		AWSSecretAccessKey: "secret",
		Region:             "us-east-1",
		Endpoint:           "minio.local:9000",
		ForcePathStyle:     true,
	}, []string{"media-bucket"})
	require.NoError(t, err)

	signedURL, signed, err = signer.Sign("https://minio.local:9000/media-bucket/foo.jpg", time.Minute)
	require.NoError(t, err)
	assert.True(t, signed)
	assert.True(t, strings.HasPrefix(signedURL, "https://minio.local:9000/media-bucket/foo.jpg?"), signedURL)
}
