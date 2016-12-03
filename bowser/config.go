package bowser

import (
	"encoding/json"
	"io/ioutil"
)

type AccountMFA struct {
	TOTP string `json:"totp"`
}

// Accounts represent individual users (auth keys) that can login
type Account struct {
	Username   string     `json:"username"`
	SSHKeysRaw []string   `json:"ssh-keys"`
	MFA        AccountMFA `json:"mfa"`
	Scopes     []string   `json:"scopes"`
	Shell      string     `json:"shell"`
}

type Config struct {
	MOTD     string `json:"motd"`
	Bind     string `json:"bind"`
	Accounts string `json:"accounts"`
	IDRSA    string `json:"id_rsa"`
	LogPath  string `json:"log_path"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result := Config{
		Bind:     "localhost:2200",
		Accounts: "accounts.json",
		IDRSA:    "id_rsa",
		LogPath:  "logs",
	}

	err = json.Unmarshal(file, &result)
	return &result, err
}

func LoadAccounts(path string) (acts []Account, err error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	err = json.Unmarshal(file, &acts)
	return
}
