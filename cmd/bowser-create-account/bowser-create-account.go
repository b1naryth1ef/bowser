package main

/*
	This script is responsible for provisioning and adding user accounts to our
	configuration. Generally it was meant to be run on the bastion box with the
	configuration path passed, thus automatically adding the account.
*/

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/discord/bowser/lib"
	"github.com/mdp/qrterminal"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
)

var accountsPath = flag.String("accounts", "", "path to accounts file")

func encryptTOTP(password []byte, salt []byte, totp []byte) ([]byte, error) {
	dk := pbkdf2.Key(password, salt, 10000, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(totp))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], totp)

	return []byte(base64.URLEncoding.EncodeToString(ciphertext)), nil
}

func readPassword(attempts int) string {
	// Create a raw terminal so we can read the password without echo
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}

	// Restore terminal
	defer terminal.Restore(0, oldState)
	defer fmt.Printf("\r\n")

	// Give the user N attempts
	for i := 0; i < attempts; i++ {
		fmt.Printf("\rPassword: ")
		a, _ := terminal.ReadPassword(0)
		fmt.Printf("\n\rConfirm: ")
		b, _ := terminal.ReadPassword(0)

		if string(a) == string(b) {
			return string(a)
		}
	}

	return ""
}

func main() {
	flag.Parse()
	reader := bufio.NewReader(os.Stdin)

	// Grab username
	fmt.Printf("Username: ")
	username, _ := reader.ReadString('\n')

	// Grab SSH Public key
	fmt.Printf("SSH Public Key: ")
	sshKey, _ := reader.ReadString('\n')

	// Grab password
	password := readPassword(3)
	if password == "" {
		return
	}
	bcryptHash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)

	// Generate TOTP code
	totpRaw := make([]byte, 32)
	_, err := rand.Read(totpRaw)
	if err != nil {
		fmt.Printf("Failed to generate TOTP token: %s\n", err)
		return
	}

	// Encode the TOTP token as base32 and truncate to 16 characters
	totpEncoded := base32.StdEncoding.EncodeToString(totpRaw)[:16]

	// Generate and display TOTP QR code
	qrterminal.Generate(fmt.Sprintf(
		"otpauth://totp/SSH:%s?secret=%s",
		username[:len(username)-1],
		totpEncoded,
	), qrterminal.H, os.Stdout)
	fmt.Printf("Please scan the above QR code with your TOTP app (or enter manually: `%s`)", totpEncoded)
	reader.ReadString('\n')

	// Now encrypt the TOTP token with the password
	totpEncrypted, err := encryptTOTP([]byte(password), []byte(username[:len(username)-1]), []byte(totpEncoded))
	if err != nil {
		fmt.Printf("Failed to encrypt TOTP token: %v\n", err)
		return
	}

	// Create a new account struct
	account := bowser.Account{
		Username:   username[:len(username)-1],
		Password:   string(bcryptHash),
		SSHKeysRaw: []string{sshKey[:len(sshKey)-1]},
		MFA:        bowser.AccountMFA{TOTP: string(totpEncrypted)},
	}

	// If we're passed an accounts file, append our data to that
	if *accountsPath != "" {
		config := bowser.Config{AccountsPath: *accountsPath}

		accounts, err := config.LoadAccounts()
		if err != nil {
			fmt.Printf("Failed to load accounts: %v\n", err)
			return
		}

		err = config.SaveAccounts(append(accounts, account))
		if err != nil {
			fmt.Printf("Failed to save accounts: %v\n", err)
			return
		}
	} else {
		// Otherwise, we just echo the payload to stdout
		data, _ := json.Marshal(account)
		fmt.Printf("\r\n%s\n", data)
	}
}
