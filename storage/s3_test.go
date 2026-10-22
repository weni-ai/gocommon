package storage_test

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"sync"
	"testing"

	"github.com/nyaruka/gocommon/storage"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/assert"
)

type testS3Client struct {
	returnError           error
	headBucketReturnValue *s3.HeadBucketOutput
	getObjectReturnValue  *s3.GetObjectOutput
	putObjectReturnValue  *s3.PutObjectOutput

	putObjectMutex  sync.Mutex
	putObjectInputs []*s3.PutObjectInput
}

func (c *testS3Client) HeadBucketWithContext(ctx context.Context, input *s3.HeadBucketInput, opts ...request.Option) (*s3.HeadBucketOutput, error) {
	if c.returnError != nil {
		return nil, c.returnError
	}
	return c.headBucketReturnValue, nil
}
func (c *testS3Client) GetObjectWithContext(ctx context.Context, input *s3.GetObjectInput, opts ...request.Option) (*s3.GetObjectOutput, error) {
	if c.returnError != nil {
		return nil, c.returnError
	}
	return c.getObjectReturnValue, nil
}
func (c *testS3Client) PutObjectWithContext(ctx context.Context, input *s3.PutObjectInput, opts ...request.Option) (*s3.PutObjectOutput, error) {
	c.putObjectMutex.Lock()
	c.putObjectInputs = append(c.putObjectInputs, input)
	c.putObjectMutex.Unlock()

	if c.returnError != nil {
		return nil, c.returnError
	}
	return c.putObjectReturnValue, nil
}

func TestNewS3Client(t *testing.T) {
	client, err := storage.NewS3Client(&storage.S3Options{
		AWSAccessKeyID:     "AKIDTEST",
		AWSSecretAccessKey: "secret",
		Region:             "sa-east-1",
		MaxRetries:         2,
	})
	assert.NoError(t, err)
	awsClient := client.(*s3.S3)
	assert.Equal(t, "https://s3.sa-east-1.amazonaws.com", awsClient.Endpoint)
	assert.Equal(t, "sa-east-1", aws.StringValue(awsClient.Config.Region))
	assert.Equal(t, 2, aws.IntValue(awsClient.Config.MaxRetries))
	assert.False(t, aws.BoolValue(awsClient.Config.S3ForcePathStyle))

	client, err = storage.NewS3Client(&storage.S3Options{
		Endpoint:       "http://localhost:9000",
		Region:         "us-east-1",
		DisableSSL:     true,
		ForcePathStyle: true,
	})
	assert.NoError(t, err)
	awsClient = client.(*s3.S3)
	assert.Equal(t, "http://localhost:9000", awsClient.Endpoint)
	assert.True(t, aws.BoolValue(awsClient.Config.DisableSSL))
	assert.True(t, aws.BoolValue(awsClient.Config.S3ForcePathStyle))
}

func TestS3Test(t *testing.T) {
	client := &testS3Client{}
	s3 := storage.NewS3(client, "mybucket", "us-east-1", 1)

	assert.NoError(t, s3.Test(context.Background()))

	client.returnError = errors.New("boom")

	assert.EqualError(t, s3.Test(context.Background()), "boom")
}

func TestS3Get(t *testing.T) {
	ctx := context.Background()
	client := &testS3Client{}
	s := storage.NewS3(client, "mybucket", "us-east-1", 1)

	client.getObjectReturnValue = &s3.GetObjectOutput{
		ContentType: aws.String("text/plain"),
		Body:        ioutil.NopCloser(bytes.NewReader([]byte(`HELLOWORLD`))),
	}

	contentType, contents, err := s.Get(ctx, "/foo/things")
	assert.NoError(t, err)
	assert.Equal(t, "text/plain", contentType)
	assert.Equal(t, []byte(`HELLOWORLD`), contents)

	client.returnError = errors.New("boom")

	_, _, err = s.Get(ctx, "/foo/things")
	assert.EqualError(t, err, "error getting S3 object: boom")
}

func TestS3Put(t *testing.T) {
	ctx := context.Background()
	client := &testS3Client{}
	s := storage.NewS3(client, "mybucket", "us-east-1", 1)

	url, err := s.Put(ctx, "/foo/things", "text/plain", []byte(`HELLOWORLD`))
	assert.NoError(t, err)
	assert.Equal(t, "https://mybucket.s3.us-east-1.amazonaws.com/foo/things", url)

	client.returnError = errors.New("boom")

	_, err = s.Put(ctx, "/foo/things", "text/plain", []byte(`HELLOWORLD`))
	assert.EqualError(t, err, "error putting S3 object: boom")
}

func TestS3BatchPut(t *testing.T) {

	ctx := context.Background()
	client := &testS3Client{}
	s := storage.NewS3(client, "mybucket", "us-east-1", 10)

	uploads := []*storage.Upload{
		{
			Path:        "https://mybucket.s3.us-east-1.amazonaws.com/foo/thing1",
			Body:        []byte(`HELLOWORLD`),
			ContentType: "text/plain",
			ACL:         s3.BucketCannedACLPrivate,
		},
		{
			Path:        "https://mybucket.s3.us-east-1.amazonaws.com/foo/thing2",
			Body:        []byte(`HELLOWORLD2`),
			ContentType: "text/plain",
			ACL:         s3.BucketCannedACLPrivate,
		},
	}

	err := s.BatchPut(ctx, uploads)
	assert.NoError(t, err)

	assert.NotEmpty(t, uploads[0].URL)
	assert.NotEmpty(t, uploads[1].URL)

	// ACLs are no longer sent
	assert.Len(t, client.putObjectInputs, 2)
	for _, input := range client.putObjectInputs {
		assert.Nil(t, input.ACL)
	}

	// try again, with a single thread and throwing an error
	s = storage.NewS3(client, "mybucket", "us-east-1", 1)
	client.returnError = errors.New("boom")

	uploads[0].URL = ""
	uploads[1].URL = ""

	err = s.BatchPut(ctx, uploads)

	assert.Error(t, err)

	assert.Empty(t, uploads[0].URL)
	assert.Empty(t, uploads[1].URL)
	assert.NotEmpty(t, uploads[0].Error)
}
