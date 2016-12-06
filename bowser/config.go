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
	MFA        AccountMFA `json:"mfa,omitempty"`
	Scopes     []string   `json:"scopes"`
	Shell      string     `json:"shell"`
}

type Config struct {
	Bind            string   `json:"bind"`
	AccountsPath    string   `json:"accounts_path"`
	IDRSAPath       string   `json:"id_rsa_path"`
	CAKeyPath       string   `json:"ca_key_path"`
	RecordingPath   string   `json:"recording_path"`
	ForceMFA        bool     `json:"force_mfa"`
	DiscordWebhooks []string `json:"discord_webhooks"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result := Config{
		Bind:          "localhost:2200",
		AccountsPath:  "accounts.json",
		IDRSAPath:     "id_rsa",
		CAKeyPath:     "ca.key",
		RecordingPath: "recordings/",
		ForceMFA:      true,
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
