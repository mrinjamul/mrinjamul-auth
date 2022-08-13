package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// ReadSecretKey reads the secret key from the file
func ReadSecretKey(filename string) ([]byte, error) {
	var key []byte
	key, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GetPEMKeyPair reads the private key and returns the PrivateKey and publicKey
func GetPEMKeyPair(key *ecdsa.PrivateKey) (privKeyPEM []byte, pubKeyPEM []byte, err error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	privKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})

	der, err = x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, err
	}

	pubKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: der,
	})

	return
}

// GenerateECDSAKey generates a new ECDSA key pair
func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // elliptic.P256() is the NIST P-256 curve
}

// GenerateSecretPEMKey generates a new PEM key pair
func GenerateSecretPEMKey(filename string) error {
	key, err := GenerateECDSAKey()
	if err != nil {
		return err
	}
	privPem, pubPem, err := GetPEMKeyPair(key)
	if err != nil {
		return err
	}

	// save both file
	err = os.WriteFile(filename+"privateKey.pem", privPem, 0600)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename+"publicKey.pem", pubPem, 0600)
	if err != nil {
		return err
	}
	return nil
}
