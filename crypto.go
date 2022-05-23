package crypto

import (
	"hash"
	"io"
)

// Hasher is a interface that provides hash algorithms
type Hasher interface {
	hash.Hash
	// Hash hashes messages msg.
	Hash(msg []byte) (hash []byte, err error)
	// BatchHash If you need to hash a series of bytes slices, calling BachHash can reduce one copy. BenchHash implies a loop.
	// example: a,b,c,d are four big byte slice
	// BenchHash([][]bytes{a,b,c,d}) faster than Hash(bytes.Join([][]bytes{a,b,c,d},nil))
	// It reduce one join(...). Join implies one copy.
	BatchHash(msg [][]byte) (hash []byte, err error)
}

// Encryptor is a interface that provides encryption algorithms
type Encryptor interface {
	// Encrypt encrypts plaintext using key k.
	Encrypt(k, plaintext []byte, reader io.Reader) (cipherText []byte, err error)
}

// Decryptor is a interface that provides decryption algorithms
type Decryptor interface {
	// Decrypt decrypts ciphertext using key k.
	Decrypt(k, cipherText []byte) (plaintext []byte, err error)
}

// Cryptor is interface that provide crypto function
//deprecated
type Cryptor interface {
	Encryptor
	Decryptor
}

// Key represents a cryptographic key
type Key interface {
	// Bytes converts this key to its byte representation,
	// if this operation is allowed.
	Bytes() ([]byte, error)

	//FromBytes It's revert method to Bytes()
	//K is a byte that needs to be parsed, and the meaning of opt depend on Keys, for example, it's maybe an algorithm type. If the parsing fails, return empty Key or nil.
	FromBytes(k []byte, opt int) error
}

// Verifier is a interface that provides verifying algorithms
type Verifier interface {
	Key
	// Verify verifies signature against key k and digest
	Verify(k, signature, digest []byte) (valid bool, err error)
}

//Signer sign
type Signer interface {
	Key
	Sign(k, digest []byte, reader io.Reader) ([]byte, error)
}
