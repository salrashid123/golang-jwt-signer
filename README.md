
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
* [crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules](https://github.com/salrashid123/signer)
* [go-tpm-tools Signer](https://pkg.go.dev/github.com/google/go-tpm-tools/client#Key.GetSigner)

Using this is really easy...you just need something that surfaces that interface.

I've written some simple ones here...the `examples/` folder uses a _PEM Signer_  (yes i'm well aware go-jwt already supports PEM format keys...i just happened to make a Signer so i could test the other ones)


The following shows the PEM signer and Google Cloud KMS based signers:

```golang

	r, err := salpem.NewPEMCrypto(&salpem.PEM{
		PrivatePEMFile: "client_rsa.key",
	})

	//salkms "github.com/salrashid123/signer/kms"
	// r, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "mineral-minutia-820",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "s",
	// 	KeyVersion:         "1",
	// 	SignatureAlgorithm: x509.SHA256WithRSA,
	// })

	rc, err := ioutil.ReadFile("client.crt")
	block, _ := pem.Decode(rc)
	c, err := x509.ParseCertificate(block.Bytes)
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Issuer:    "test",
	}

	yk.SigningMethodSignerRS256.Override()
	token := jwt.NewWithClaims(yk.SigningMethodSignerRS256, claims)

	keyctx, err := yk.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: r,
	})
	token.Header["kid"] = "1212"

	tokenString, err := token.SignedString(keyctx)
	fmt.Printf("TOKEN: %s\n", tokenString)
```

The output is a signed JWT

```log
# cd examples/

$ go run main.go 
TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMTIiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NjAzMjk2OTcsImlzcyI6InRlc3QifQ.jcvMEHXKVAdjgGQM6n7U9y0wkJKIdwCmQu2SNrz67L6G5gN0aGBGVaANcQ4iCJ3BM-r92GCdzIr3SlDtBs9C-9EDXzIygp41Xct66jbeqcJ4Udkf_5nHDgKyyMuxLnlkQO5SD9aZYHacJtv34P7THeAA6WUoVhsTYg5QvE0pDDkWf4PYeADh_gP7wnFha1jjjwMDPWhNyJhxSICBQ4I8s_s8FhWNr_shXqMwYPZj3fEabHbsRAZIEr8Y2nQAsQHAE97rU8CutShsQeY59WkHy04zx2HHbBepM6nnSHqtWFkh12eT4-8TvaMBNX9yv20ln6OHaKaIf3RpsreAFPf_TQ
2022/08/12 14:40:37      verified with Signer PublicKey
2022/08/12 14:40:37      verified with exported PubicKey
```



The JWT is formatted as:

```json
{
  "alg": "RS256",
  "kid": "1212",
  "typ": "JWT"
}
{
  "exp": 1660329697,
  "iss": "test"
}
```

