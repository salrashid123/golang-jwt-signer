package jwtsigner

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestRSA(t *testing.T) {

	// demo signer
	privatePEM, err := os.ReadFile("example/certs/client_rsa.key")
	require.NoError(t, err)

	rblock, _ := pem.Decode(privatePEM)

	r, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)
	require.NoError(t, err)
	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	SigningMethodSignerRS256.Override()
	token := jwt.NewWithClaims(SigningMethodSignerRS256, claims)

	keyctx, err := NewSignerContext(ctx, &SignerConfig{
		Signer: r,
	})
	require.NoError(t, err)

	token.Header["kid"] = "1212"
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := SignerVerfiyKeyfunc(context.Background(), &SignerConfig{
		Signer: r,
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestRSAPSS(t *testing.T) {

	// demo signer
	privatePEM, err := os.ReadFile("example/certs/client_rsa_pss.key")
	require.NoError(t, err)

	rblock, _ := pem.Decode(privatePEM)

	r, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)
	require.NoError(t, err)
	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	SigningMethodSignerPS256.Override()
	token := jwt.NewWithClaims(SigningMethodSignerPS256, claims)

	keyctx, err := NewSignerContext(ctx, &SignerConfig{
		Signer: r,
	})
	require.NoError(t, err)

	token.Header["kid"] = "1212"
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := SignerVerfiyKeyfunc(context.Background(), &SignerConfig{
		Signer: r,
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestECC(t *testing.T) {
	// demo signer
	privatePEM, err := os.ReadFile("example/certs/client_ec.key")
	require.NoError(t, err)

	rblock, _ := pem.Decode(privatePEM)

	r, err := x509.ParseECPrivateKey(rblock.Bytes)
	require.NoError(t, err)
	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	SigningMethodSignerES256.Override()
	token := jwt.NewWithClaims(SigningMethodSignerES256, claims)

	keyctx, err := NewSignerContext(ctx, &SignerConfig{
		Signer: r,
	})
	require.NoError(t, err)

	token.Header["kid"] = "1212"
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := SignerVerfiyKeyfunc(context.Background(), &SignerConfig{
		Signer: r,
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}
