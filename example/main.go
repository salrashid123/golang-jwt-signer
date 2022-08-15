package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	//"github.com/go-piv/piv-go/piv"
	"github.com/golang-jwt/jwt"
	jwtsigner "github.com/salrashid123/golang-jwt-signer"
	salpem "github.com/salrashid123/signer/pem"
	// salkms "github.com/salrashid123/signer/kms"
	// saltpm "github.com/salrashid123/signer/tpm"
	// "github.com/ThalesIgnite/crypto11"
	// salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"
)

var ()

func main() {

	ctx := context.Background()

	// first initialize a crypto.Signer

	// demo signer
	r, err := salpem.NewPEMCrypto(&salpem.PEM{
		PrivatePEMFile: "client_rsa.key",
	})

	// // rsa.PrivateKey also implements a crypto.Signer
	// // https://pkg.go.dev/crypto/rsa#PrivateKey.Sign
	// privatePEM, err := ioutil.ReadFile("client_rsa.key")
	// if err != nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }
	// rblock, _ := pem.Decode(privatePEM)
	// if rblock == nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }
	// r, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)
	// if err != nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }

	// ############# KMS

	// r, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "mineral-minutia-820",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "s",
	// 	KeyVersion:         "1",
	// })

	// ############# TPM

	// r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmDevice:     "/dev/tpm0",
	// 	TpmHandleFile: "/tmp/key.bin",
	// 	//TpmHandle:     0x81010002,
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

	// export SOFTHSM2_CONF=/path/to/softhsm.conf
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
	// 	Context:        cctx,
	// 	PkcsId:         nil,                 //softhsm
	// 	PkcsLabel:      []byte("keylabel1"), //softhsm
	// 	PublicCertFile: "client.crt",        //softhsm
	// })

	if err != nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}

	// ===================================

	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
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
	token.Header["kid"] = "1212"

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

	// verify with provided RSAPublic key

	rc, err := ioutil.ReadFile("client.crt")
	if err != nil {
		fmt.Println(err)
		return
	}

	block, _ := pem.Decode(rc)

	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	pubKey := c.PublicKey

	v, err := jwt.Parse(vtoken.Raw, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}

}
