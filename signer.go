package jwtsigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	jwt "github.com/golang-jwt/jwt"
)

type SignerConfig struct {
	Signer crypto.Signer
}

type signerConfigKey struct{}

func (k *SignerConfig) GetPublicKey() crypto.PublicKey {
	return k.Signer.Public()
}

var (
	SigningMethodSignerRS256 *SigningMethodCryptoSigner
	errMissingConfig         = errors.New("signer: missing configuration in provided context")
	errMissingSigner         = errors.New("signer: Signer not available")
)

type SigningMethodCryptoSigner struct {
	alg      string
	override jwt.SigningMethod
	hasher   crypto.Hash
}

func NewSignerContext(parent context.Context, val *SignerConfig) (context.Context, error) {
	return context.WithValue(parent, signerConfigKey{}, val), nil
}

func SignerFromContext(ctx context.Context) (*SignerConfig, bool) {
	val, ok := ctx.Value(signerConfigKey{}).(*SignerConfig)
	return val, ok
}

func init() {
	// RS256
	SigningMethodSignerRS256 = &SigningMethodCryptoSigner{
		"SignerRS256",
		jwt.SigningMethodRS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerRS256
	})

	// todo: restructure and allow for RSA-PSS PS256
	// SigningMethodSignerPS256 = &SigningMethodCryptoSigner{
	// 	"SignerPS256",
	// 	jwt.SigningMethodRP256,
	// 	crypto.SHA256,
	// }
	// jwt.RegisterSigningMethod(SigningMethodSignerP256.Alg(), func() jwt.SigningMethod {
	// 	return SigningMethodSignerPS256
	// })
}

func (s *SigningMethodCryptoSigner) Alg() string {
	return s.alg
}

func (s *SigningMethodCryptoSigner) Override() {
	s.alg = s.override.Alg()
	jwt.RegisterSigningMethod(s.alg, func() jwt.SigningMethod {
		return s
	})
}

func (s *SigningMethodCryptoSigner) Hash() crypto.Hash {
	return s.hasher
}

func (s *SigningMethodCryptoSigner) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}

	config, ok := SignerFromContext(ctx)
	if !ok {
		return "", errMissingConfig
	}

	message := []byte(signingString)
	hasher := s.Hash().New()
	_, err := hasher.Write(message)
	if err != nil {
		return "", fmt.Errorf("error hashing YubiKey: %v", err)
	}

	hashed := hasher.Sum(message[:0])

	rng := rand.Reader

	signedBytes, err := config.Signer.Sign(rng, hashed, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf(" error from signing from YubiKey: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(signedBytes), nil
}

func SignerVerfiyKeyfunc(ctx context.Context, config *SignerConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.GetPublicKey(), nil
	}, nil
}

func (s *SigningMethodCryptoSigner) Verify(signingString, signature string, key interface{}) error {
	return s.override.Verify(signingString, signature, key)
}
