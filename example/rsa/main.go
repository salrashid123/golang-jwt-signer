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

	// first initialize a crypto.Signer

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

	// ############# KMS

	// r, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:  "srashid-test2",
	// 	LocationId: "us-central1",
	// 	KeyRing:    "kr",
	// 	Key:        "rskey1",
	// 	KeyVersion: "1",
	// })

	// ############# TPM

	// r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmPath:   "/dev/tpm0",
	// 	KeyHandle: uint32(0x81008001),
	// })

	// ############# Yubikey

	// cards, err := piv.Cards()
	// if err != nil {
	// 	fmt.Printf("unable to open yubikey %v", err)
	// 	os.Exit(1)
	// }
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
	// if ykey == nil {
	// 	fmt.Printf("yubikey not found Please make sure the key is inserted %v", err)
	// 	os.Exit(1)
	// }
	// defer ykey.Close()

	// cert, err := ykey.Certificate(piv.SlotSignature)
	// if err != nil {
	// 	fmt.Printf("unable to load certificate not found %v", err)
	// 	os.Exit(0)
	// }

	// auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	// priv, err := ykey.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	// if err != nil {
	// 	fmt.Printf("unable to load privateKey %v", err)
	// 	os.Exit(0)
	// }

	// r, ok := priv.(crypto.Signer)
	// if !ok {
	// 	fmt.Printf("expected private key to implement crypto.Signer")
	// 	os.Exit(0)
	// }

	// ############# PKCS11

	// export SOFTHSM2_CONF=/tmp/golang-jwt-pkcs11/test_data/softhsm.conf
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	// 	TokenLabel: "token1",
	// 	Pin:        "mynewpin",
	// }

	// cctx, err := crypto11.Configure(config)
	// if err != nil {
	// 	fmt.Printf("error creating pkcs11 config%v", err)
	// 	os.Exit(0)
	// }
	// defer cctx.Close()

	// r, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
	// 	Context:   cctx,
	// 	PkcsId:    nil,                 //softhsm
	// 	PkcsLabel: []byte("keylabel1"), //softhsm
	// })

	// if err != nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }

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
