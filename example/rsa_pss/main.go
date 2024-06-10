package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

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

	// ===================================  RSA  PSS

	// i'm just using a plain rsa key which implements the singer.
	// see the README.md in this repo for examples with TPM, KMS, PKCS-11

	// demo signer RSA
	pssprivatePEM, err := os.ReadFile("certs/client_rsa_pss.key")
	if err != nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}
	rpssblock, _ := pem.Decode(pssprivatePEM)
	if rpssblock == nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}
	rpss, err := x509.ParsePKCS1PrivateKey(rpssblock.Bytes)
	if err != nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}

	pssclaims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	jwtsigner.SigningMethodSignerPS256.Override()
	psstoken := jwt.NewWithClaims(jwtsigner.SigningMethodSignerPS256, pssclaims)

	psskeyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: rpss,
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}
	psstoken.Header["kid"] = "1212"

	psstokenString, err := psstoken.SignedString(psskeyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	fmt.Printf("PSS TOKEN: %s\n", psstokenString)

	// // verify with embedded publickey
	psskeyFunc, err := jwtsigner.SignerVerfiyKeyfunc(ctx, &jwtsigner.SignerConfig{
		Signer: rpss,
	})
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	pssvtoken, err := jwt.Parse(psstokenString, psskeyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if pssvtoken.Valid {
		log.Println("     verified PSS with Signer PublicKey")
	}
}
