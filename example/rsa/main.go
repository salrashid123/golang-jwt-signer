package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-signer"
)

var ()

func main() {

	ctx := context.Background()

	// first initialize a crypto.Signer

	// i'm just using a plain rsa key which implements the singer.
	// see the README.md in this repo for examples with TPM, KMS, PKCS-11

	// demo signer RSA
	privatePEM, err := os.ReadFile("certs/client_rsa.key")
	if err != nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}
	rblock, _ := pem.Decode(privatePEM)
	if rblock == nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}
	r, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)
	if err != nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}

	// ===================================  RSA

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	jwtsigner.SigningMethodSignerRS256.Override()
	token := jwt.NewWithClaims(jwtsigner.SigningMethodSignerRS256, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: r,
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}
	token.Header["kid"] = "4142"

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	fmt.Printf("TOKEN: %s\n", tokenString)

	// // verify with embedded publickey
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(ctx, &jwtsigner.SignerConfig{
		Signer: r,
	})
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("     verified with Signer PublicKey")
	}

}
