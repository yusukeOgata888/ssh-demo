package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)


func main() {
	// Generate ephemeral keys for server and client
	serverEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	// Get the public key of the server
	serverPub := serverEphemeral.PublicKey();

	// Generate ephemeral keys for client
	clientEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	// Get the public key of the client
	clientPub := clientEphemeral.PublicKey();
	
	// Perform ECDH
	sharedSecretServer, err := serverEphemeral.ECDH(clientPub)
	if err != nil {
		panic(err)
	}
	sharedSecretClient, err := clientEphemeral.ECDH(serverPub)
	if err != nil {	
		panic(err)
	}

	// Check if the shared secrets are equal
	if !equalBytes(sharedSecretServer, sharedSecretClient) {
		panic("shared secrets are not equal")
	}

	// Print the shared secret
	sharedSecret := sharedSecretServer
	fmt.Println("shared secret:", sharedSecret)
	// Derive the session id
	sessionId := sha256.Sum256(sharedSecret)
	fmt.Println("session id:", sessionId[:])

	// Generate signing keys for server
	clientSigningPub, clientSigningPrv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)	
	}

	// Generate signing keys for client
	signature := ed25519.Sign(clientSigningPrv, sessionId[:])
	fmt.Println("signature:", signature[:8])

	// Verify the signature
	ok := ed25519.Verify(clientSigningPub, sessionId[:], signature)
	if ok {
		fmt.Println("signature is valid")
	} else {
		fmt.Println("signature is invalid")
	}
}	
	func equalBytes(a, b []byte) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}