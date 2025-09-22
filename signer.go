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
	SigningMethodSignerRS384 *SigningMethodCryptoSigner
	SigningMethodSignerRS512 *SigningMethodCryptoSigner

	SigningMethodSignerPS256 *SigningMethodCryptoSigner
	SigningMethodSignerPS384 *SigningMethodCryptoSigner
	SigningMethodSignerPS512 *SigningMethodCryptoSigner

	SigningMethodSignerES256 *SigningMethodCryptoSigner
	SigningMethodSignerES384 *SigningMethodCryptoSigner
	SigningMethodSignerES512 *SigningMethodCryptoSigner

	errMissingConfig = errors.New("signer: missing configuration in provided context")
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

	// RS384
	SigningMethodSignerRS384 = &SigningMethodCryptoSigner{
		"SignerRS384",
		jwt.SigningMethodRS384,
		crypto.SHA384,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerRS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerRS384
	})

	// RS512
	SigningMethodSignerRS512 = &SigningMethodCryptoSigner{
		"SignerRS512",
		jwt.SigningMethodRS512,
		crypto.SHA512,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerRS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerRS512
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

	// PS384
	SigningMethodSignerPS384 = &SigningMethodCryptoSigner{
		"SignerPS384",
		jwt.SigningMethodPS384,
		crypto.SHA384,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerPS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerPS384
	})

	// PS512
	SigningMethodSignerPS512 = &SigningMethodCryptoSigner{
		"SignerPS512",
		jwt.SigningMethodPS512,
		crypto.SHA512,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerPS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerPS512
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

	// ES384
	SigningMethodSignerES384 = &SigningMethodCryptoSigner{
		"SignerES384",
		jwt.SigningMethodES384,
		crypto.SHA384,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerES384.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerES384
	})

	// ES512
	SigningMethodSignerES512 = &SigningMethodCryptoSigner{
		"SignerES512",
		jwt.SigningMethodES512,
		crypto.SHA512,
	}
	jwt.RegisterSigningMethod(SigningMethodSignerES512.Alg(), func() jwt.SigningMethod {
		return SigningMethodSignerES512
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
	switch s.alg {
	case "PS256", "PS384", "PS512":
		opts := &rsa.PSSOptions{
			Hash:       s.Hash(),
			SaltLength: rsa.PSSSaltLengthAuto,
		}
		signedBytes, err = config.Signer.Sign(rng, hashed, opts)
		if err != nil {
			return nil, fmt.Errorf(" error from signing from : %v", err)
		}
	case "ES256", "ES384", "ES512":

		signedBytes, err = config.Signer.Sign(rng, hashed, s.Hash())
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
	case "RS256", "RS384", "RS512":
		signedBytes, err = config.Signer.Sign(rng, hashed, s.Hash())
		if err != nil {
			return nil, fmt.Errorf(" error from signing from : %v", err)
		}
	default:
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
