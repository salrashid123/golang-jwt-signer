module main

go 1.19

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/salrashid123/golang-jwt-signer v0.0.0
	github.com/salrashid123/signer/pem v0.0.0-20220718102027-af49b1c9153d
)

replace github.com/salrashid123/golang-jwt-signer => ../
