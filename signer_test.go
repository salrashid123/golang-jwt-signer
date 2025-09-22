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

	tests := []struct {
		name          string
		signingMethod *SigningMethodCryptoSigner
	}{
		{"AlgSHA256", SigningMethodSignerRS256},
		{"AlgSHA384", SigningMethodSignerRS384},
		{"AlgSHA512", SigningMethodSignerRS512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			claims := &jwt.RegisteredClaims{
				ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
				Issuer:    "test",
			}

			var token *jwt.Token

			switch tc.signingMethod {
			case SigningMethodSignerRS256:
				SigningMethodSignerRS256.Override()
				token = jwt.NewWithClaims(SigningMethodSignerRS256, claims)

			case SigningMethodSignerRS384:
				SigningMethodSignerRS384.Override()
				token = jwt.NewWithClaims(SigningMethodSignerRS384, claims)

			case SigningMethodSignerRS512:
				SigningMethodSignerRS512.Override()
				token = jwt.NewWithClaims(SigningMethodSignerRS512, claims)
			}

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

		})
	}

}

func TestRSAPSS(t *testing.T) {

	// demo signer
	privatePEM, err := os.ReadFile("example/certs/client_rsa_pss.key")
	require.NoError(t, err)

	rblock, _ := pem.Decode(privatePEM)

	r, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name          string
		signingMethod *SigningMethodCryptoSigner
	}{
		{"AlgSHA256", SigningMethodSignerPS256},
		{"AlgSHA384", SigningMethodSignerPS384},
		{"AlgSHA512", SigningMethodSignerPS512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := &jwt.RegisteredClaims{
				ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
				Issuer:    "test",
			}

			var token *jwt.Token

			switch tc.signingMethod {
			case SigningMethodSignerPS256:
				SigningMethodSignerPS256.Override()
				token = jwt.NewWithClaims(SigningMethodSignerPS256, claims)

			case SigningMethodSignerPS384:
				SigningMethodSignerPS384.Override()
				token = jwt.NewWithClaims(SigningMethodSignerPS384, claims)

			case SigningMethodSignerPS512:
				SigningMethodSignerPS512.Override()
				token = jwt.NewWithClaims(SigningMethodSignerPS512, claims)
			}

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

		})
	}

}

func TestECC(t *testing.T) {

	tests := []struct {
		name          string
		signingMethod *SigningMethodCryptoSigner
		keyPath       string
	}{
		{"AlgSHA256", SigningMethodSignerES256, "example/certs/client_ec.key"},
		{"AlgSHA384", SigningMethodSignerES384, "example/certs/client_ec_385.key"},
		{"AlgSHA512", SigningMethodSignerES512, "example/certs/client_ec_512.key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			// demo signer
			privatePEM, err := os.ReadFile(tc.keyPath)
			require.NoError(t, err)

			rblock, _ := pem.Decode(privatePEM)

			r, err := x509.ParseECPrivateKey(rblock.Bytes)
			require.NoError(t, err)
			ctx := context.Background()
			claims := &jwt.RegisteredClaims{
				ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
				Issuer:    "test",
			}

			var token *jwt.Token

			switch tc.signingMethod {
			case SigningMethodSignerES256:
				SigningMethodSignerES256.Override()
				token = jwt.NewWithClaims(SigningMethodSignerES256, claims)

			case SigningMethodSignerES384:
				SigningMethodSignerES384.Override()
				token = jwt.NewWithClaims(SigningMethodSignerES384, claims)

			case SigningMethodSignerES512:
				SigningMethodSignerES512.Override()
				token = jwt.NewWithClaims(SigningMethodSignerES512, claims)
			}

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

		})
	}

}
