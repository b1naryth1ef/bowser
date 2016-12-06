package bowser

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/uber-go/zap"
	"golang.org/x/crypto/ssh"
)

type SSHDState struct {
	Config *Config

	WebhookProviders []WebhookProvider
	ca               *CertificateAuthority
	log              zap.Logger
	accounts         map[string]*Account
	keys             map[string]*AccountKey
}

func NewSSHDState() *SSHDState {
	config, err := LoadConfig("config.json")

	if err != nil {
		log.Panicf("Failed to load config: %v", err)
	}

	ca, err := NewCertificateAuthority(config.CAKeyPath)

	if err != nil {
		log.Panicf("Failed to load CA key file: %v", err)
	}

	providers := make([]WebhookProvider, 0)

	for _, url := range config.DiscordWebhooks {
		providers = append(providers, DiscordWebhookProvider{URL: url})
	}

	state := SSHDState{
		Config:           config,
		WebhookProviders: providers,
		ca:               ca,
		log:              zap.New(zap.NewJSONEncoder()),
	}

	// Ensure the logpath exists
	os.Mkdir(state.Config.RecordingPath, 0770)

	state.reloadAccounts()
	return &state
}

func (s *SSHDState) reloadAccounts() {
	rawAccounts, err := LoadAccounts(s.Config.AccountsPath)
	if err != nil {
		s.log.Error("Failed to load accounts", zap.Error(err))
		return
	}

	accounts := make(map[string]*Account)
	keys := make(map[string]*AccountKey)

	for _, account := range rawAccounts {
		if _, exists := accounts[account.Username]; exists {
			s.log.Error("Duplicate username", zap.String("username", account.Username))
			return
		}

		accounts[account.Username] = &account

		for _, key := range account.SSHKeysRaw {
			key, err := NewAccountKey(&account, []byte(key))
			if err != nil {
				s.log.Warn(
					"Skipping key for account, couldn't parse",
					zap.Error(err),
					zap.Object("account", account))
				continue
			}

			other, exists := keys[key.ID()]
			if exists {
				s.log.Error("Duplicate key", zap.Object("account a", other.Account), zap.Object("account b", account))
				return
			}

			keys[key.ID()] = key
		}

	}

	s.accounts = accounts
	s.keys = keys
}

var badKeyError = fmt.Errorf("This is not the castle you are looking for...")

func (s *SSHDState) Run() {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			accountKey, exists := s.keys[string(key.Marshal())]

			// If we don't have that key, just gtfo
			if !exists {
				return nil, badKeyError
			}

			if conn.User() != accountKey.Account.Username {
				return nil, badKeyError
			}

			return nil, nil
		},
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile(s.Config.IDRSAPath)
	if err != nil {
		log.Fatalf("Failed to load private key (%v)", s.Config.IDRSAPath)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	sshConfig.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", s.Config.Bind)
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	log.Printf("Listening on %v", s.Config.Bind)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			s.log.Warn(
				"Failed to handshake",
				zap.Error(err))
			continue
		}

		session := NewSSHSession(s, sshConn)

		s.log.Info(
			"New SSH connection",
			zap.String("remote", sshConn.RemoteAddr().String()),
			zap.String("version", string(sshConn.ClientVersion())))

		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)

		// Run the core loop which handles channels
		go session.handleChannels(chans)
	}
}
