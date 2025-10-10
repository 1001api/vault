package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.design/x/clipboard"

	"1001api.com/vault/internal"
)

var (
	version     = "1.0.0"
	saltLength  = 16
	dekLength   = 32
	vaultPath   = filepath.Join(os.Getenv("HOME"), ".vault.json")
	idLength    = 6
	nonceLength = 12

	// Table width
	tableWidth       = 60
	noColWidth       = 5
	idColWidth       = 6
	siteColWidth     = 24
	usernameColWidth = 20
)

func main() {
	if err := clipboard.Init(); err != nil {
		log.Fatal("failed to init clipboard", err)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: vault <command>")
		fmt.Println("Commands:")
		fmt.Println("  init			Initialize vault")
		fmt.Println("  unlock		Unlock vault and start interactive mode")
		os.Exit(1)
	}

	cmd := os.Args[1]

	vaultService := internal.CreateVaultService()
	ioService := internal.NewIOService(vaultPath)

	switch cmd {
	case "init":
		// Initialize vault
		initVault(vaultService, ioService)
	case "unlock":
		// Unlock vault
		dek := unlockVault(vaultService, ioService)

		fmt.Print("\n")
		fmt.Println("🔓 Vault unlocked successfully.")

		interactiveMode(vaultService, ioService, dek)
	default:
		fmt.Println("Invalid command")
		os.Exit(1)
	}
}

func initVault(vaultService internal.VaultService, ioService internal.IOService) {
	// Check if vault file exists
	if ioService.CheckFileExists() {
		log.Fatal("vault file already exists, aborting...")
	}

	// Ask user for password (securely)
	fmt.Print("Create master password: ")
	password, err := ioService.AskPassword()
	if err != nil {
		log.Fatal("failed to ask password", err)
	}

	fmt.Print("\nConfirm master password: ")
	confirmPassword, err := ioService.AskPassword()
	if err != nil {
		log.Fatal("failed to ask password", err)
	}

	if string(password) != string(confirmPassword) {
		log.Fatal("passwords do not match")
	}

	// Generate random 16 bytes salt
	salt := vaultService.GenerateRandomSecureKey(saltLength)

	// Derive Key Encryption Key (KEK) using argon2
	kek := vaultService.DeriveKEK(password, salt)

	// Generate random 32 bytes key as a Data Encryption Key (DEK)
	dek := vaultService.GenerateRandomSecureKey(dekLength)

	// Encrypt DEK using KEK
	nonce, wrappedDEK := vaultService.EncryptAESGCM(kek, dek)

	// Vault Data Type
	vault := internal.Vault{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrappedDEK),
		NonceDEK:   base64.StdEncoding.EncodeToString(nonce),
		Version:    version,
		CreatedAt:  time.Now().Unix(),
		Entries:    []internal.Entry{},
	}

	// Initialize vault file
	initVaultFile(&vault, ioService)

	fmt.Println("\n✅ Vault initialized successfully.")
}

func initVaultFile(v *internal.Vault, ioService internal.IOService) {
	if v == nil {
		log.Fatal("vault is nil before initVaultFile")
	}

	// Create vault file
	file, err := ioService.CreateFile()
	if err != nil {
		log.Fatal("failed to create vault file", err)
	}
	defer file.Close()

	json.NewEncoder(file).Encode(v)
}

func unlockVault(vaultService internal.VaultService, ioService internal.IOService) []byte {
	// Check if vault file exists
	if !ioService.CheckFileExists() {
		log.Fatal("vault file does not exist, please run 'init' first")
	}

	// Ask user for password
	fmt.Print("Enter master password: ")
	password, err := ioService.AskPassword()
	if err != nil {
		log.Fatal("failed to ask password", err)
	}

	// Read vault file
	vault := ioService.ReadVaultFile()

	saltDecoded, _ := base64.StdEncoding.DecodeString(vault.Salt)
	wrappedDEKDecoded, _ := base64.StdEncoding.DecodeString(vault.WrappedDEK)
	nonceDEKDecoded, _ := base64.StdEncoding.DecodeString(vault.NonceDEK)

	kek := vaultService.DeriveKEK(password, saltDecoded)
	dek := vaultService.DecryptAESGCM(kek, nonceDEKDecoded, wrappedDEKDecoded)

	// Zero out the kek slice to prevent memory leaks
	for i := range password {
		password[i] = 0
	}
	for i := range kek {
		kek[i] = 0
	}

	return dek
}

func interactiveMode(vaultService internal.VaultService, ioService internal.IOService, dek []byte) {
	fmt.Println("Type 'help' to see available commands.")

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("vault> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		args := strings.Fields(input)

		if len(args) == 0 {
			continue
		}

		switch args[0] {
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  add <site> <username> -> Add a new entry")
			fmt.Println("  get <id/site> -> Get an entry")
			fmt.Println("  list -> List all entries")
			fmt.Println("  remove <id> -> Remove an entry")
			fmt.Println("  lock -> Lock & exit vault")
		case "add":
			if len(args) != 3 {
				fmt.Println("Usage: add <site> <username>")
				continue
			}

			// prompt secure password
			fmt.Print("Enter entry password: ")
			password, err := ioService.AskPassword()
			if err != nil {
				log.Fatal("failed to ask password", err)
			}

			addEntry(vaultService, ioService, dek, args[1], args[2], password)
		case "get":
			if len(args) != 2 {
				fmt.Println("Usage: get <id/site>")
				continue
			}

			identifier := args[1]

			getEntry(vaultService, ioService, dek, identifier)
		case "list":
			listEntries(ioService)
		case "remove":
			if len(args) != 2 {
				fmt.Println("Usage: remove <id>")
				continue
			}

			id := args[1]

			removeEntry(ioService, id)
		case "lock":
			fmt.Println("🔒 Vault locked successfully.")
			os.Exit(0)
		default:
			fmt.Println("Invalid command")
		}
	}
}

func addEntry(
	vaultService internal.VaultService,
	ioService internal.IOService,
	dek []byte,
	site, username string,
	password []byte,
) {
	vault := ioService.ReadVaultFile()

	// Generate a unique, secure random ID for the entry.
	// Uses vaultService for crypto-secure randomness using nanoid.
	id := vaultService.GenerateRandomID(idLength)

	// Encrypt the password using AES-GCM.
	// This produces a nonce (for uniqueness) and ciphertext (encrypted data).
	// vaultService handles the encryption details securely.
	nonce, cipherText := vaultService.EncryptAESGCM(dek, password)

	// Prepare the encrypted password field.
	// Concatenate nonce + ciphertext, then base64-encode for safe storage/transmission.
	// Base64 ensures the binary data is representable as a string in the Entry struct.
	encryptedPassword := base64.StdEncoding.EncodeToString(append(nonce, cipherText...))

	entry := internal.Entry{
		ID:       id,
		Site:     site,
		Username: username,
		Password: encryptedPassword,
	}

	// Add the new entry to the vault.
	vault.Entries = append(vault.Entries, entry)

	// Save the updated vault to disk.
	ioService.SaveVaultFile(vault)

	fmt.Println("✅ Entry added successfully")
}

func getEntry(
	vaultService internal.VaultService,
	ioService internal.IOService,
	dek []byte,
	identifier string,
) {
	vault := ioService.ReadVaultFile()

	// Loop through entries
	// Search for entry by ID
	for _, entry := range vault.Entries {
		if entry.ID != identifier && entry.Site != identifier {
			continue
		}

		fmt.Println(strings.Repeat("=", tableWidth))
		fmt.Printf("Site:     %s\n", entry.Site)
		fmt.Printf("Username: %s\n", entry.Username)
		fmt.Println(strings.Repeat("-", tableWidth))

		// Decrypt password
		decodedBase64Password, _ := base64.StdEncoding.DecodeString(entry.Password)

		// Check if decodedBase64Password is valid
		if len(decodedBase64Password) < nonceLength {
			log.Fatal("invalid encrypted password format")
		}

		// Extract nonce from the first 12 bytes
		nonce := decodedBase64Password[:nonceLength]

		// Extract cipher text from the remaining bytes
		cipherText := decodedBase64Password[nonceLength:]

		// Decrypt password
		plainPassword := vaultService.DecryptAESGCM(dek, nonce, cipherText)

		// Copy to clipboard
		clipboard.Write(clipboard.FmtText, []byte(plainPassword))

		fmt.Println("🔑 Password copied to clipboard.")
		fmt.Println(strings.Repeat("=", tableWidth))

		// Cleanup memory
		// Zero out the plainPassword slice to prevent memory leaks
		for i := range plainPassword {
			plainPassword[i] = 0
		}

		return
	}

	fmt.Println("Entry not found")
}

func listEntries(ioService internal.IOService) {
	vault := ioService.ReadVaultFile()

	if len(vault.Entries) == 0 {
		fmt.Println("No entries found")
		return
	}

	// Print the top border using the defined table width.
	// A line of equals signs visually frames the table for better scannability.
	fmt.Println(strings.Repeat("=", tableWidth))

	// Print the header row with column labels.
	// Formatted with left-aligned columns using %-width specifiers.
	// The pipe characters (|) act as visual separators between columns.
	// Total width aligns with tableWidth for a clean look.
	fmt.Printf("%-*s | %-*s | %-*s | %-*s\n",
		noColWidth, "No.",
		idColWidth, "ID",
		siteColWidth, "Site",
		usernameColWidth, "Username",
	)

	// Print the header underline with dashes.
	// This creates a clear visual distinction between the header and data rows.
	fmt.Println(strings.Repeat("-", tableWidth))

	// Print each entry row with formatted values.
	// Each column aligns with its specified width.
	for index, entry := range vault.Entries {
		fmt.Printf("%-*d | %-*s | %-*s | %-*s\n",
			noColWidth, index+1,
			idColWidth, entry.ID,
			siteColWidth, entry.Site,
			usernameColWidth, entry.Username)
	}

	fmt.Println(strings.Repeat("-", tableWidth))
	fmt.Println("Total entries:", len(vault.Entries))
}

func removeEntry(ioService internal.IOService, id string) {
	vault := ioService.ReadVaultFile()

	var entryFound bool

	// Iterate over entries
	for index, entry := range vault.Entries {
		if entry.ID != id {
			continue
		}

		entryFound = true

		// Remove the entry from the slice.
		// append(vault.Entries[:index], vault.Entries[index+1:]...) effectively
		// creates a new slice without the element at "index".
		vault.Entries = append(vault.Entries[:index], vault.Entries[index+1:]...)

		// Save the vault file
		ioService.SaveVaultFile(vault)

		// Notify the user and exit the function early.
		fmt.Println("✅ Entry removed successfully.")

		return
	}

	if !entryFound {
		fmt.Println("❌ Entry not found")
	}
}
