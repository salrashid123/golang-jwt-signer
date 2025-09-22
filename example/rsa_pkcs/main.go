package main

import (
	"context"
	"fmt"
	"log"
	"time"

	//"github.com/go-piv/piv-go/piv"

	"github.com/ThalesGroup/crypto11"
	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-signer"

	salpkcs "github.com/salrashid123/pkcssigner"
)

var ()

// export SOFTHSM2_CONF=/tmp/softhsm.conf

func main() {

	ctx := context.Background()

	config := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		TokenLabel: "token1",
		Pin:        "mynewpin",
	}

	cctx, err := crypto11.Configure(config)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cctx.Close()

	r, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
		Context:   cctx,
		PkcsId:    nil,                 //softhsm
		PkcsLabel: []byte("keylabel1"), //softhsm
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
