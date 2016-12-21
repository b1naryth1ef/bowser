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
	Password   string     `json:"password"`
	SSHKeysRaw []string   `json:"ssh-keys"`
	MFA        AccountMFA `json:"mfa,omitempty"`
	Scopes     []string   `json:"scopes"`
}

// The base config which stores mostly paths and some general configuration info
type Config struct {
	Bind            string   `json:"bind"`
	AccountsPath    string   `json:"accounts_path"`
	IDRSAPath       string   `json:"id_rsa_path"`
	CAKeyPath       string   `json:"ca_key_path"`
	DiscordWebhooks []string `json:"discord_webhooks"`
	ForceCommand    string   `json:"force_command"`
	ForceUser       string   `json:"force_user"`
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
