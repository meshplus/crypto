package crypto

import (
	"hash"
	"io"
)

//Engine crypto engine
type Engine interface {
	PluginRandomFunc
	PluginHashFunc
	PluginCryptFunc
	PluginVerifyFunc
	PluginSignFunc
	PluginCreateSignFunc
	PluginEncKeyFunc
	PluginDecKeyFunc
	PluginCreateDecKeyFunc
	SetAlgo([]byte) error
	GetDefaultAlgo() (int, int)
}

//SecretKey sym
type SecretKey interface {
	Encrypt(src []byte, reader io.Reader) []byte
	Decrypt(src []byte) []byte
	Destroy()
}

//PublicKey represents the public key, capable of verification and encryption
type PublicKey interface {
	VerifyKey
	EncKey
}

//PrivateKey represents the private key, able to sign and decrypt
type PrivateKey interface {
	SignKey
	DecKey
}

//SignKey private key which can sign
type SignKey interface {
	VerifyKey
	Sign(msg []byte, hasher hash.Hash, rand io.Reader) ([]byte, error)
	Destroy()
}

//VerifyKey public key which can verify
type VerifyKey interface {
	GetKeyInfo() int
	Verify(msg []byte, hasher hash.Hash, sig []byte) bool
	//return a raw
	//sm2: SM2PublicKey::=BIT STRING,	04||X||Y,	65 Bytes,	GMT0009-2012 7.1
	//ecdsa: PublicKeyBytes in PKIX publicKey
	//rsa: asn1{N, e}
	//for more information, see GetVerifyKey's comment
	Bytes() []byte
}

//EncKey public key which can encrypt
type EncKey interface {
	GetKeyInfo() int
	Encrypt(msg []byte, reader io.Reader) ([]byte, error)
	//for more information, see  comment of VerifyKey.Bytes
	Bytes() []byte
}

//DecKey private key which can decrypt
type DecKey interface {
	EncKey
	Decrypt(cipher []byte) ([]byte, error)
	Destroy()
}

const (
	//Hash message digest algorithm
	Hash = 0
	//Asymmetric asymmetric encryption algorithm
	Asymmetric = 8
	//Symmetrical symmetric encryption algorithm
	Symmetrical = 16
)

//algorithm identifier const value table
const (
	//None unknown algorithm type, type information is hidden in the content, for example PKCS8
	None = 0x0

	//Hash
	FakeHash         = 0x00 << Hash
	SHA1             = 0x10 << Hash
	SHA2             = 0x20 << Hash
	SHA3             = 0x30 << Hash
	KECCAK           = 0x40 << Hash
	SM3              = 0x50 << Hash
	Sm3WithPublicKey = 0x60 << Hash //with default SM2 userID: 1234567812345678
	Size224          = 0x01 << Hash
	Size256          = 0x00 << Hash
	Size384          = 0x02 << Hash
	Size512          = 0x03 << Hash
	SHA2_224         = SHA2 | Size224
	SHA2_256         = SHA2 | Size256
	SHA2_384         = SHA2 | Size384
	SHA2_512         = SHA2 | Size512
	SHA3_224         = SHA3 | Size224
	SHA3_256         = SHA3 | Size256
	SHA3_384         = SHA3 | Size384
	SHA3_512         = SHA3 | Size512
	KECCAK_224       = KECCAK | Size224
	KECCAK_256       = KECCAK | Size256
	KECCAK_384       = KECCAK | Size384
	KECCAK_512       = KECCAK | Size512

	//Asymmetric Algo
	Sm2p256v1        = 0x01 << Asymmetric
	Secp256k1        = 0x02 << Asymmetric
	Secp256r1        = 0x03 << Asymmetric
	Secp384r1        = 0x04 << Asymmetric
	Secp521r1        = 0x05 << Asymmetric
	Secp256k1Recover = 0x06 << Asymmetric
	Rsa2048          = 0x10 << Asymmetric
	Rsa3072          = 0x11 << Asymmetric
	Rsa4096          = 0x12 << Asymmetric
	Ed25519          = 0x20 << Asymmetric

	//Symmetrical Algo for Encrypt and Decrypt
	Sm4  = 0x01 << Symmetrical
	Aes  = 0x02 << Symmetrical
	Des3 = 0x03 << Symmetrical
	TEE  = 0x04 << Symmetrical
	CBC  = 0x10 << Symmetrical
	ECB  = 0x20 << Symmetrical
	GCM  = 0x30 << Symmetrical
)

//Level priority of plugins
type Level interface {
	GetLevel() ([]int, uint8)
}

//PluginRandomFunc random function
type PluginRandomFunc interface {
	Level
	Rander() (io.Reader, error)
}

//PluginHashFunc hash function
type PluginHashFunc interface {
	Level
	GetHash(mode int) (Hasher, error)
}

//PluginCryptFunc symmetric encryption and decryption function
type PluginCryptFunc interface {
	Level
	GetSecretKey(mode int, pwd, key []byte) (SecretKey, error)
}

//PluginVerifyFunc verify function
type PluginVerifyFunc interface {
	Level
	//enter a raw publicKey and mod, return a VerifyKey
	//a raw publicKey means:
	// 1) for sm2, key is 65bytes and in 0x04||X||Y form, see GMT0009-2012 7.1
	//      http://www.gmbz.org.cn/main/viewfile/2018011001400692565.html may help
	// 2) for ecdsa, key is in 0x04||X||Y. The length depends on the curve, for example,
	//		65 bytes for secp256k1 and 133 for secp521r1, see 2.3.3 in [SEC1] uncompressed form.
	//		https://www.rfc-editor.org/rfc/rfc5480.txt may help
	// 3) for rsa, key is in PKCS#1 form, see RFC2313 RSAPublicKey
	//		RSAPublicKey ::= SEQUENCE {
	//     		modulus INTEGER, -- n
	//     		publicExponent INTEGER -- e }
	//		https://www.rfc-editor.org/rfc/rfc2313.txt may help
	GetVerifyKey(key []byte, mode int) (VerifyKey, error)
}

//PluginSignFunc sign function
type PluginSignFunc interface {
	Level
	//enter index or raw privat key to generate a SignKey, key will not be persistent
	// a raw private key is a big integer
	GetSignKey(key []byte, mode int) (SignKey, error)
	//enter raw private key, return index, key should be persistent
	ImportSignKey(key []byte, mode int) (index []byte, err error)
}

//PluginCreateSignFunc create SignKey
type PluginCreateSignFunc interface {
	Level
	//generate a SignKey, and return index or key in raw form
	//if persistent is true, key should be persistent and return index
	//	or persistent is false, key should be persistent and output should in raw form
	CreateSignKey(persistent bool, mode int) (index []byte, k SignKey, err error)
}

//PluginEncKeyFunc asymmetric encryption function
type PluginEncKeyFunc interface {
	Level
	//enter a raw publicKey and mod, return a VerifyKey
	//see GetVerifyKey's comment for the meaning of a raw publicKey
	GetEncKey(key []byte, mode int) (EncKey, error)
}

//PluginDecKeyFunc asymmetric decryption function
type PluginDecKeyFunc interface {
	Level
	//enter index or raw privat key to generate a DecKey, key will not be persistent
	// a raw private key is a big integer
	GetDecKey(key []byte, mode int) (DecKey, error)
	//enter raw private key, return index, key should be persistent
	ImportDecKey(key []byte, mode int) (index []byte, err error)
}

//PluginCreateDecKeyFunc create decryption function
type PluginCreateDecKeyFunc interface {
	Level
	//generate a DecKey, and return index or key in raw form
	//if persistent is true, key should be persistent and return index
	//	or persistent is false, key should be persistent and output should in raw form
	CreateDecKey(persistent bool, mode int) (index []byte, k DecKey, err error)
}

//FlagReader reader use as flag
type FlagReader interface {
	io.Reader
	GetFlag() int
}
