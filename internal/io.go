package internal

import (
	"encoding/json"
	"log"
	"os"

	"golang.org/x/term"
)

type IOService interface {
	CheckFileExists() bool
	CreateFile() (*os.File, error)
	AskPassword() ([]byte, error)
	ReadVaultFile() *Vault
	SaveVaultFile(vault *Vault)
}

type ioService struct {
	vaultPath string
}

func NewIOService(vaultPath string) IOService {
	return &ioService{
		vaultPath: vaultPath,
	}
}

func (s *ioService) CheckFileExists() bool {
	fileInfo, err := os.Stat(s.vaultPath)
	if err != nil {
		return false
	}
	return fileInfo != nil
}

func (s *ioService) CreateFile() (*os.File, error) {
	file, err := os.Create(s.vaultPath)
	if err != nil {
		log.Fatal("failed to create vault file", err)
	}
	return file, nil
}

func (s *ioService) ReadVaultFile() *Vault {
	// Read vault file
	file, err := os.ReadFile(s.vaultPath)
	if err != nil {
		log.Fatal("failed to read vault file", err)
	}

	// Unmarshal vault file
	var vault Vault
	if err := json.Unmarshal(file, &vault); err != nil {
		log.Fatal("failed to unmarshal vault file", err)
	}

	return &vault
}

func (s *ioService) SaveVaultFile(vault *Vault) {
	// Marshal vault file
	file, err := json.Marshal(vault)
	if err != nil {
		log.Fatal("failed to marshal vault file", err)
	}

	// Write vault file
	if err := os.WriteFile(s.vaultPath, file, 0600); err != nil {
		log.Fatal("failed to write vault file", err)
	}
}

func (s *ioService) AskPassword() ([]byte, error) {
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal("failed to read password", err)
	}
	return pass, nil
}
