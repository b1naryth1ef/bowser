package bowser

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/pquerna/otp/totp"
	"github.com/uber-go/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

const (
	VERSION = "v0.0.1"
)

type SSHDState struct {
	Config *Config

	WebhookProviders []WebhookProvider
	ca               *CertificateAuthority
	log              zap.Logger
	accounts         map[string]*Account
	keys             map[string]*AccountKey

	// Caches a session ID, to the validity state
	sessionValidityCache map[string]*Account
}

func NewSSHDState(configPath string) *SSHDState {
	// Load our configuration
	config, err := LoadConfig(configPath)
	if err != nil {
		log.Panicf("Failed to load config: %v", err)
	}

	// Load our SSH CA
	ca, err := NewCertificateAuthority(config.CAKeyPath)
	if err != nil {
		log.Panicf("Failed to load CA key file: %v", err)
	}

	// Load all the webhook providers
	providers := make([]WebhookProvider, 0)
	for _, url := range config.DiscordWebhooks {
		providers = append(providers, DiscordWebhookProvider{URL: url})
	}

	state := SSHDState{
		Config:               config,
		WebhookProviders:     providers,
		ca:                   ca,
		log:                  zap.New(zap.NewJSONEncoder()),
		sessionValidityCache: make(map[string]*Account),
	}

	state.reloadAccounts()
	return &state
}

func (s *SSHDState) reloadAccounts() {
	rawAccounts, err := s.Config.loadAccounts()
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

var badKeyError = fmt.Errorf("Invalid SSH key")
var badPasswordError = fmt.Errorf("Invalid password")
var badMFAError = fmt.Errorf("Invalid MFA code")

func (s *SSHDState) Run() {
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: false,

		ServerVersion: fmt.Sprintf("SSH-2.0-bowser-%s", VERSION),

		// Function to handle public key verification
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			accountKey, exists := s.keys[string(key.Marshal())]

			// If the key doesn't exist, just break
			if !exists {
				return nil, badKeyError
			}

			// If the username doesn't match, break
			if conn.User() != accountKey.Account.Username {
				return nil, badKeyError
			}

			// Mark that this sessions SSH key was validated in the cache
			s.sessionValidityCache[string(conn.SessionID())] = accountKey.Account

			// Finally, even though we've validated a public key for this session, we
			//  return an error as if we had not. This forces the client to authenticate
			//  in the keyboard interactive mode, allowing us to capture their password
			//  and mfa token. Later on, we can validate that the user actually owns
			//  the public key above by requesting they sign random data with the key
			//  using their SSH agent.
			return nil, badKeyError
		},

		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// Make sure their SSH key was previously validated
			account, exists := s.sessionValidityCache[string(conn.SessionID())]
			if !exists {
				return nil, badKeyError
			}

			// Request and validate the clients password
			passwordAnswer, err := client(conn.User(), "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, badPasswordError
			}

			// Check if the password matches
			err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(passwordAnswer[0]))
			if err != nil {
				return nil, badPasswordError
			}

			// Request and validate the clients MFA code
			var verified bool

			for i := 0; i < 3; i++ {
				mfaAnswer, err := client(conn.User(), "", []string{"MFA Token: "}, []bool{true})

				if err != nil {
					continue
				}

				if totp.Validate(mfaAnswer[0], account.MFA.TOTP) {
					verified = true
					break
				}
			}

			if !verified {
				return nil, badMFAError
			}

			return nil, nil
		},
	}

	// Load our ID-RSA private key into memory
	privateBytes, err := ioutil.ReadFile(s.Config.IDRSAPath)
	if err != nil {
		log.Fatalf("Failed to load private key (%v)", s.Config.IDRSAPath)
	}

	// Parse the private key
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	// Add it to our SSHD configuration
	sshConfig.AddHostKey(private)

	// Open a TCP listener on the bind address requested
	listener, err := net.Listen("tcp", s.Config.Bind)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %s", s.Config.Bind, err)
	}

	// Begin listening and accepting connections
	log.Printf("Listening on %v", s.Config.Bind)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		// After opening the connection, attempt a handshake
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			s.log.Warn("Failed to handshake", zap.Error(err))
			continue
		}

		// Open the SSH session struct on the connection
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
