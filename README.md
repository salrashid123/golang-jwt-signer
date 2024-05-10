
# golang-jwt for crypto.Signer

Another extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) that allows creating and verifying JWT tokens where the private key is abstracted as something that is accessible through the [crypto.Signer](https://pkg.go.dev/crypto#Signer) interface.


The out of the obx `go-jwt` normally expects you to directly provide an [rsa.PrivateKey](https://pkg.go.dev/github.com/golang-jwt/jwt#readme-choosing-a-signing-method) object.  That is normally just fine if you have a key bytes handy in some sort of local storage.  

`go-jwt` can be [extended](https://github.com/golang-jwt/jwt#extensions) to support arbitrary providers holding the key.  In this case, you can have the private key saved into KMS, Yubikeys, Hashicorp Vault or even a Trusted Platform Module.

Each 'backend' you choose to save the keys to requires you to import that package and use that directly.

In contrast, the implementation describes here takes it a step back where you define any key backend that would implement the `crypto.Signer` interface and then provide that directly into a library.  

Instead of importing a use-specific golang-jwt implementation and using that, what we'll do here is just provide a generic `Signer`.


>> This code is NOT supported by google

For other references, see:

* [golang-jwt for Trusted Platform Module TPM](https://github.com/salrashid123/golang-jwt-tpm)
* [golang-jwt for Yubikey](https://github.com/salrashid123/golang-jwt-yubikey)
* [golang-jwt for PKCS11](https://github.com/salrashid123/golang-jwt-pkcs11)
* [golang-jwt for TPM](https://github.com/salrashid123/golang-jwt-tpm)
* [crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules](https://github.com/salrashid123/signer)
* [go-tpm-tools Signer](https://pkg.go.dev/github.com/google/go-tpm-tools/client#Key.GetSigner)

### Supported Algorithms

* `RS256`
* `PS256`
* `ES256`

### Usage

Using this is really easy...you just need something that surfaces that interface.

I've written some simple ones here...the `examples/` folder uses a _PEM Signer_  (yes i'm well aware go-jwt already supports PEM format keys...i just happened to make a Signer so i could test the other ones)


The following shows the PEM signer and Google Cloud KMS based signers:

```golang
package main

import (

	//"github.com/go-piv/piv-go/piv"
	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-signer"

	// salkms "github.com/salrashid123/signer/kms"
	// saltpm "github.com/salrashid123/signer/tpm"
	// "github.com/ThalesIgnite/crypto11"
	// salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"
)

var ()

func main() {

	ctx := context.Background()

	// // rsa.PrivateKey also implements  crypto.Signer
	// // https://pkg.go.dev/crypto/rsa#PrivateKey.Sign
	privatePEM, err := os.ReadFile("client_rsa.key")
	rblock, _ := pem.Decode(privatePEM)
	r, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)

	// ############# for a KMS signer

	// r, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "mineral-minutia-820",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "s",
	// 	KeyVersion:         "1",
	// })

	// ############# for a TPM singer

	// r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmPath:     "/dev/tpm0",
	// 	KeyHandle: uint32(0x81010002),
	// })

	// ############# for a Yubikey singer

	// cards, err := piv.Cards()
	// var ykey *piv.YubiKey
	// for _, card := range cards {
	// 	if strings.Contains(strings.ToLower(card), "yubikey") {
	// 		if ykey, err = piv.Open(card); err != nil {
	// 			fmt.Printf("unable to open yubikey %v", err)
	// 			os.Exit(1)
	// 		}
	// 		break
	// 	}
	// }
	// defer ykey.Close()

	// cert, err := ykey.Certificate(piv.SlotSignature)
	// auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	// priv, err := ykey.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	// r, ok := priv.(crypto.Signer)


	// ############# for a general PKCS11 signer

	// export SOFTHSM2_CONF=/path/to/softhsm.conf
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	// 	TokenLabel: "token1",
	// 	Pin:        "mynewpin",
	// }

	// cctx, err := crypto11.Configure(config)

	// defer cctx.Close()

	// r, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
	// 	Context:        cctx,
	// 	PkcsId:         nil,                 //softhsm
	// 	PkcsLabel:      []byte("keylabel1"), //softhsm
	// })


	// ===================================

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	jwtsigner.SigningMethodSignerRS256.Override()
	token := jwt.NewWithClaims(jwtsigner.SigningMethodSignerRS256, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: r,
	})

	token.Header["kid"] = "1212"

	tokenString, err := token.SignedString(keyctx)

	fmt.Printf("TOKEN: %s\n", tokenString)

	// // verify with embedded publickey
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(ctx, &jwtsigner.SignerConfig{
		Signer: r,
	})

	vtoken, err := jwt.Parse(tokenString, keyFunc)

	if vtoken.Valid {
		log.Println("     verified with Signer PublicKey")
	}

}
```

The output is a signed JWT

```log
# cd examples/

$ go run main.go 
TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMTIiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NjAzMjk2OTcsImlzcyI6InRlc3QifQ.jcvMEHXKVAdjgGQM6n7U9y0wkJKIdwCmQu2SNrz67L6G5gN0aGBGVaANcQ4iCJ3BM-r92GCdzIr3SlDtBs9C-9EDXzIygp41Xct66jbeqcJ4Udkf_5nHDgKyyMuxLnlkQO5SD9aZYHacJtv34P7THeAA6WUoVhsTYg5QvE0pDDkWf4PYeADh_gP7wnFha1jjjwMDPWhNyJhxSICBQ4I8s_s8FhWNr_shXqMwYPZj3fEabHbsRAZIEr8Y2nQAsQHAE97rU8CutShsQeY59WkHy04zx2HHbBepM6nnSHqtWFkh12eT4-8TvaMBNX9yv20ln6OHaKaIf3RpsreAFPf_TQ
2022/08/12 14:40:37      verified with Signer PublicKey
2022/08/12 14:40:37      verified with exported PubicKey
```
