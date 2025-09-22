package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
	jwtsigner "github.com/salrashid123/golang-jwt-signer"
)

var ()

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	ctx := context.Background()

	// using swtpm here,
	rwc, err := OpenTPM("127.0.0.1:2321")
	if err != nil {
		fmt.Printf("can't open TPM: %v", err)
		return
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Printf("can't close TPM: %v", err)
		}
	}()

	persistentHandle := 0x81008001

	// using go-tpm-tools.client.Key
	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(persistentHandle), nil)
	if err != nil {
		log.Fatalf("Error getting key: %v", err)
	}
	r, err := k.GetSigner()
	if err != nil {
		log.Fatalf("Error getting signer: %v", err)
	}

	// using github/salrashid123/signer/tpm
	// rwr := transport.FromReadWriter(rwc)
	// pub, err := tpm2.ReadPublic{
	// 	ObjectHandle: tpm2.TPMHandle(persistentHandle),
	// }.Execute(rwr)

	// r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmDevice: rwc,
	// 	NamedHandle: &tpm2.NamedHandle{
	// 		Handle: tpm2.TPMHandle(persistentHandle),
	// 		Name:   pub.Name,
	// 	},
	// })

	if err != nil {
		log.Fatalf("Error getting singer: %v", err)
	}

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
