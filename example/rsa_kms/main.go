package main

import (
	"context"
	"fmt"
	"log"
	"time"

	//"github.com/go-piv/piv-go/piv"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-signer"
	salkms "github.com/salrashid123/kms_golang_signer"
)

var ()

func main() {

	ctx := context.Background()

	r, err := salkms.NewKMSCrypto(&salkms.KMS{
		ProjectId:  "core-eso",
		LocationId: "us-central1",
		KeyRing:    "kr",
		Key:        "rskey1",
		KeyVersion: "1",
	})

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
