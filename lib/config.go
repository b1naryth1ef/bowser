package bowser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"regexp"

	"golang.org/x/crypto/pbkdf2"
)

type AccountMFA struct {
	TOTP string `json:"totp"`
}

// Accounts represent individual users (auth keys) that can login
type Account struct {
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	SSHKeysRaw  []string          `json:"ssh-keys"`
	MFA         AccountMFA        `json:"mfa,omitempty"`
	Whitelist   string            `json:"whitelist"`
	Blacklist   string            `json:"blacklist"`
	PlatformIDs map[string]string `json:"platform_ids"`

	whitelistRe *regexp.Regexp
	blacklistRe *regexp.Regexp
}

// The base config which stores mostly paths and some general configuration info
type Config struct {
	Bind                     string   `json:"bind"`
	AccountsPath             string   `json:"accounts_path"`
	IDRSAPath                string   `json:"id_rsa_path"`
	CAKeyPath                string   `json:"ca_key_path"`
	DiscordWebhooks          []string `json:"discord_webhooks"`
	ForceCommand             string   `json:"force_command"`
	ForceUser                string   `json:"force_user"`
	PermittedSourceAddresses []string `json:"permitted_source_addresses"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result := Config{
		Bind:         "localhost:2200",
		AccountsPath: "accounts.json",
		IDRSAPath:    "id_rsa",
		CAKeyPath:    "ca.key",
	}

	err = json.Unmarshal(file, &result)
	return &result, err
}

func (c *Config) LoadAccounts() (acts []Account, err error) {
	file, err := ioutil.ReadFile(c.AccountsPath)
	if err != nil {
		return
	}

	err = json.Unmarshal(file, &acts)
	return
}

func (c *Config) SaveAccounts(acts []Account) (err error) {
	data, err := json.MarshalIndent(acts, "", "  ")
	if err != nil {
		return
	}

	// TODO: consider adding sanity checks here

	err = ioutil.WriteFile(c.AccountsPath, data, 644)
	return
}

func (am *AccountMFA) decryptTOTP(password []byte, salt []byte) (string, error) {
	dk := pbkdf2.Key(password, salt, 10000, 32, sha1.New)

	ciphertext, _ := base64.URLEncoding.DecodeString(am.TOTP)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", err
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
