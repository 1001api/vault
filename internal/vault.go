package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"

	"github.com/sixafter/nanoid"
	"golang.org/x/crypto/argon2"
)

var (
	// How many iterations of the Argon2 algorithm to perform
	// higher = more secure but slower
	// lower = faster but less secure
	// recommended: 1 for development, 2/3 for production
	argon2Time = 2

	// How much memory (in KiB = 1024 bytes) to use while hashing.
	// It's a main defense against GPU attacks since it makes the operation
	// memory-intensive. Which limits GPU's ability to perform parallel
	// computations.
	argon2Memory = 128 * 1024 // 128 KiB = 128 MiB

	// How many threads argon used. Depends on the number of CPU cores.
	// Smaller server or embedded might have only 1 core. So adjust
	// accordingly.
	argon2Parallelism = 4

	// The length of final derived key in bytes.
	argon2KeyLength = 32
)

type VaultService interface {
	DeriveKEK(value []byte, salt []byte) []byte
	GenerateRandomSecureKey(length int) []byte
	GenerateRandomID(length int) string
	EncryptAESGCM(key, plainText []byte) (nonce, cipherText []byte)
	DecryptAESGCM(key, nonce, cipherText []byte) []byte
}

type vaultService struct{}

func CreateVaultService() VaultService {
	return &vaultService{}
}

func (s *vaultService) DeriveKEK(value []byte, salt []byte) []byte {
	return argon2.IDKey(
		value,
		salt,
		uint32(argon2Time),
		uint32(argon2Memory),
		uint8(argon2Parallelism),
		uint32(argon2KeyLength),
	)
}

func (s *vaultService) GenerateRandomSecureKey(length int) []byte {
	key := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatal("failed to generate random secure key", err)
	}
	return key
}

func (s *vaultService) GenerateRandomID(length int) string {
	id, err := nanoid.NewWithLength(length)
	if err != nil {
		log.Fatal("failed to generate random ID", err)
	}
	return id.String()
}

func (s *vaultService) EncryptAESGCM(key, plainText []byte) (nonce, cipherText []byte) {
	// Initializing AES block.
	// Think of it as initializing the AES machine.
	// If key is not valid 16, 24 or 32 bytes, it will throw error.
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("failed to create AES cipher", err)
	}

	// Wrap AES block with Galois Counter Mode (GCM).
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("failed to create AES GCM", err)
	}

	// GCM needs a unique random number used once (nonce) for every enc.
	// This is not a secret, but must never repeat every encryption.
	nonce = make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal("failed to generate random nonce", err)
	}

	// Does the actual encryption.
	cipherText = aesgcm.Seal(nil, nonce, plainText, nil)

	return nonce, cipherText
}

func (s *vaultService) DecryptAESGCM(key, nonce, cipherText []byte) []byte {
	// Initializing AES block.
	// Think of it as initializing the AES machine.
	// If key is not valid 16, 24 or 32 bytes, it will throw error.
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("failed to create AES cipher", err)
	}

	// Wrap AES block with Galois Counter Mode (GCM).
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("failed to create AES GCM", err)
	}

	// Does the actual decryption.
	plainText, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatal("failed to decrypt AES GCM", err)
	}

	return plainText
}
