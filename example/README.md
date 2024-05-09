### Examples


#### TPM

```bash
## for rsapersistentHandle

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001

## for eccpersistentHandle

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002


## for policyRSApersistentHandle

 tpm2_startauthsession -S session.dat
 tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
 tpm2_flushcontext session.dat
 tpm2_createprimary -C o -c primary2.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa2.pub -r rsa2.priv -C primary2.ctx  -L policy.dat
 tpm2_load -C primary2.ctx -u rsa2.pub -r rsa2.priv -c rsa2.ctx
 tpm2_evictcontrol -C o -c rsa2.ctx 0x81008004
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

For PKCS see

- [golang-jwt for PKCS11](https://github.com/salrashid123/golang-jwt-pkcs11)


once you set that up, you can use this library as a `crypto.Singer`


```bash
cd /tmp/
git clone https://github.com/salrashid123/golang-jwt-pkcs11
cd golang-jwt-pkcs11/

# vi  softhsm.com
#   log.level = DEBUG
#   objectstore.backend = file
#   directories.tokendir = /tmp/golang-jwt-pkcs11/test_data
#   slots.removable = false


export SOFTHSM2_CONF=/tmp/golang-jwt-pkcs11/test_data/softhsm.conf

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-mechanisms --slot-index 0

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4142 --label keylabel1 --pin mynewpin

```