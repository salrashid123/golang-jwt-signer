### Examples


#### TPM

If you want to use a swtpm instead of a real one:

```bash
rm -rf /tmp/tokens/ && mkdir /tmp/tokens
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
```

```bash
### for swtpm
# export TPM2TOOLS_TCTI="swtpm:port=2321"


## for rsapersistentHandle

 tpm2_createprimary -C o -c primary.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_flushcontext -t 
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001
 tpm2_flushcontext -t
 
## for eccpersistentHandle

 tpm2_createprimary -C o -c primary.ctx
 tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
 tpm2_flushcontext -t
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002
 tpm2_flushcontext -t

## for policyRSApersistentHandle

 tpm2_startauthsession -S session.dat
 tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
 tpm2_flushcontext session.dat
 tpm2_createprimary -C o -c primary2.ctx
 tpm2_flushcontext -t 
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa2.pub -r rsa2.priv -C primary2.ctx  -L policy.dat
 tpm2_load -C primary2.ctx -u rsa2.pub -r rsa2.priv -c rsa2.ctx
 tpm2_evictcontrol -C o -c rsa2.ctx 0x81008004
 tpm2_flushcontext -t 
```

#### KMS

Using GCP KMS provider

```bash
gcloud kms keyrings create kr  --location=us-central1

## rsa-sign-pkcs1-2048-sha256
gcloud kms keys create rskey1 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pkcs1-2048-sha256

## rsa-sign-pss-2048-sha256
gcloud kms keys create rskey2 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pss-2048-sha256

## ec-sign-p256-sha256
gcloud kms keys create ec1 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=ec-sign-p256-sha256

```


### YubiKey

For Yubikey, you need to first have a certificate on the PIV.  See 

- [golang-jwt for Yubikey](https://github.com/salrashid123/golang-jwt-yubikey)

once you set that up, you can use this library as a `crypto.Singer`

### PKCS11


For PKCS, we'll use [SoftHSM](https://www.opendnssec.org/softhsm/) (see example installation [here](https://github.com/salrashid123/golang-jwt-pkcs11?tab=readme-ov-file#setup-softhsm))

or as a quickstart

```bash
cd /tmp/
rm -rf /tmp/tokens/ && mkdir /tmp/tokens
```

create a file called softhsm.conf with the following content

```conf
log.level = DEBUG
objectstore.backend = file
directories.tokendir = /tmp/tokens
slots.removable = false
```


Now on the `certs/` folder of this repo, convert the key to DER

```bash
cd certs/
# openssl rsa -in client.key -outform DER -out client_key.der
# openssl x509 -outform DER -in client.crt -out client_cert.der
```

Import the key and certificate using `pkcs11-tool`


```bash
export SOFTHSM2_CONF=/tmp/softhsm.conf
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4142 --label keylabel1 --pin mynewpin
```

remember to set the 


```bash
export SOFTHSM2_CONF=/tmp/softhsm.conf
```

then run `example/rsa_pkcs/main.go` and run


Also see [golang-jwt for PKCS11](https://github.com/salrashid123/golang-jwt-pkcs11)


```