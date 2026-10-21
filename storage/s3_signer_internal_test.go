package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebIdentityProvider(t *testing.T) {
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_ROLE_SESSION_NAME"} {
		t.Setenv(name, "")
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("jwt"), 0600))

	sess, err := session.NewSession()
	require.NoError(t, err)

	// no web identity env, so the default chain is left alone
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_ROLE_ARN", "")
	assert.Nil(t, webIdentityProvider(sess, &S3Options{}))

	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	assert.Nil(t, webIdentityProvider(sess, &S3Options{}), "role ARN is required")

	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/test")

	provider := webIdentityProvider(sess, &S3Options{})
	require.NotNil(t, provider)
	assert.Equal(t, DefaultCredentialsExpiryWindow, provider.ExpiryWindow)

	provider = webIdentityProvider(sess, &S3Options{CredentialsExpiryWindow: 5 * time.Minute})
	require.NotNil(t, provider)
	assert.Equal(t, 5*time.Minute, provider.ExpiryWindow)

	// static keys win over web identity, whether configured or from the env
	assert.Nil(t, webIdentityProvider(sess, &S3Options{AWSAccessKeyID: "AKIDTEST", AWSSecretAccessKey: "secret"}))

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDENV")
	assert.NotNil(t, webIdentityProvider(sess, &S3Options{}), "env access key alone isn't a credential")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	assert.Nil(t, webIdentityProvider(sess, &S3Options{}))
}
