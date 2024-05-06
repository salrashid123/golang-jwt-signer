package jwtsigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	jwt "github.com/golang-jwt/jwt/v5"
)

type SignerConfig struct {
	Signer           crypto.Signer
	keyid            string           // (optional) the  keyID
	publicKeyFromTPM crypto.PublicKey // the public key as read signer
}

type signerConfigKey struct{}

func (k *SignerConfig) GetPublicKey() crypto.PublicKey {
	return k.Signer.Public()
}

var (
	SigningMethodSignerRS256 *SigningMethodCryptoSigner
	SigningMethodSignerPS256 *SigningMethodCryptoSigner
	SigningMethodSignerES256 *SigningMethodCryptoSigner
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

	// ES256
	SigningMethodSignerES256 = &SigningMethodCryptoSigner{
		"SignerES256",
		jwt.SigningMethodES256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerES256.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerES256
	})

	// PS256
	SigningMethodSignerPS256 = &SigningMethodCryptoSigner{
		"SignerPS256",
		jwt.SigningMethodPS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerPS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerPS256
	})

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

func (s *SigningMethodCryptoSigner) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}

	config, ok := SignerFromContext(ctx)
	if !ok {
		return nil, errMissingConfig
	}

	message := []byte(signingString)
	hasher := s.Hash().New()
	_, err := hasher.Write(message)
	if err != nil {
		return nil, fmt.Errorf("error hashing : %v", err)
	}

	hashed := hasher.Sum(message[:0])

	rng := rand.Reader

	var signedBytes []byte
	if s.alg == "PS256" {
		opts := &rsa.PSSOptions{
			Hash:       crypto.SHA256,
			SaltLength: rsa.PSSSaltLengthAuto,
		}
		signedBytes, err = config.Signer.Sign(rng, hashed, opts)
		if err != nil {
			return nil, fmt.Errorf(" error from signing from : %v", err)
		}
	} else if s.alg == "ES256" {

		signedBytes, err = config.Signer.Sign(rng, hashed, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf(" error from signing from : %v", err)
		}
		epub, ok := config.GetPublicKey().(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("tpmjwt: error converting ECC keytype %v", err)
		}
		curveBits := epub.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}
		out := make([]byte, 2*keyBytes)
		var sigStruct struct{ R, S *big.Int }
		_, err := asn1.Unmarshal(signedBytes, &sigStruct)
		if err != nil {
			return nil, fmt.Errorf("jwt: can't unmarshall ecc struct %v", err)
		}
		sigStruct.R.FillBytes(out[0:keyBytes])
		sigStruct.S.FillBytes(out[keyBytes:])
		return out, nil
	} else if s.alg == "RS256" {
		signedBytes, err = config.Signer.Sign(rng, hashed, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf(" error from signing from : %v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported signature type %v", s.alg)
	}

	return signedBytes, nil
}

func SignerVerfiyKeyfunc(ctx context.Context, config *SignerConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.GetPublicKey(), nil
	}, nil
}

func (s *SigningMethodCryptoSigner) Verify(signingString string, signature []byte, key interface{}) error {
	return s.override.Verify(signingString, signature, key)
}
