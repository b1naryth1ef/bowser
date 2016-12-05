package bowser

import (
	"encoding/json"
	"fmt"
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

// Remote Hosts represent remote hosts this bastion could connect too
type RemoteHost struct {
	Hostname string   `json:"hostname"`
	Port     int      `json:"port"`
	Scopes   []string `json:"scopes"`
}

func (rh *RemoteHost) ToString() string {
	return fmt.Sprintf("%v:%v", rh.Hostname, rh.Port)
}

type Config struct {
	MOTD            string `json:"motd"`
	Bind            string `json:"bind"`
	AccountsPath    string `json:"accounts_path"`
	RemoteHostsPath string `json:"remote_hosts_path"`
	IDRSAPath       string `json:"id_rsa_path"`
	RecordingPath   string `json:"recording_path"`
	ForceMFA        bool   `json:"force_mfa"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result := Config{
		Bind:            "localhost:2200",
		AccountsPath:    "accounts.json",
		RemoteHostsPath: "hosts.json",
		IDRSAPath:       "id_rsa",
		RecordingPath:   "recordings/",
		ForceMFA:        true,
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

func LoadRemoteHosts(path string) (hosts []RemoteHost, err error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	err = json.Unmarshal(file, &hosts)
	return
}
