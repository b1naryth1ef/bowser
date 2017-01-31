package bowser

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"syscall"

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
	sessions         map[string]*SSHSession

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
		sessions:             make(map[string]*SSHSession),
	}

	state.reloadAccounts()
	return &state
}

func (s *SSHDState) reloadAccounts() {
	rawAccounts, err := s.Config.LoadAccounts()
	if err != nil {
		s.log.Error("Failed to load accounts", zap.Error(err))
		return
	}

	accounts := make(map[string]*Account)
	keys := make(map[string]*AccountKey)

	for aid := range rawAccounts {
		account := rawAccounts[aid]

		if _, exists := accounts[account.Username]; exists {
			s.log.Error("Duplicate username", zap.String("username", account.Username))
			return
		}

		accounts[account.Username] = &account

		if account.Whitelist != "" {
			account.whitelistRe, err = regexp.Compile(account.Whitelist)
			if err != nil {
				s.log.Error("Failed to parse whitelist regex", zap.String("regex", account.Whitelist))
				return
			}
		}

		if account.Blacklist != "" {
			account.blacklistRe, err = regexp.Compile(account.Blacklist)
			if err != nil {
				s.log.Error("Failed to parse blacklist regex", zap.String("regex", account.Blacklist))
				return
			}
		}

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

	// Now, iterate over sessions and close any invalid ones
	for _, session := range s.sessions {
		if _, exists := accounts[session.Account.Username]; !exists {
			s.log.Warn(
				"Closing session for user that was deleted from accounts",
				zap.String("username", session.Account.Username),
				zap.String("session", session.UUID))

			session.Close()
		}
	}
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
				s.log.Warn(
					"Username did not match SSH key",
					zap.String("conn-username", conn.User()),
					zap.String("key-username", accountKey.Account.Username))
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
				s.log.Warn(
					"Could not find session in validity cache",
					zap.String("session-id", string(conn.SessionID())))
				return nil, badKeyError
			}

			// Request and validate the clients password
			passwordAnswer, err := client(conn.User(), "", []string{"Password: "}, []bool{false})
			if err != nil {
				s.log.Warn(
					"SSH Client did not accept our keyboard interactive request",
					zap.String("username", conn.User()),
					zap.Error(err))
				return nil, badPasswordError
			}

			// Check if the password matches
			err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(passwordAnswer[0]))
			if err != nil {
				s.log.Warn(
					"Incorrect password",
					zap.String("username", conn.User()))
				return nil, badPasswordError
			}

			// If the user has MFA enabled, request and validate their MFA code/token
			if account.MFA.TOTP == "" {
				var verified bool

				for i := 0; i < 3; i++ {
					mfaAnswer, err := client(conn.User(), "", []string{"MFA Code: "}, []bool{true})

					if err != nil {
						continue
					}

					if totp.Validate(mfaAnswer[0], account.MFA.TOTP) {
						verified = true
						break
					}
				}

				if !verified {
					s.log.Warn(
						"Incorrect MFA code",
						zap.String("username", conn.User()))
					return nil, badMFAError
				}
			}

			s.log.Info("Completed basic authentication checks", zap.String("username", conn.User()))
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

	// Start listening for SIGHUP (e.g. reload accounts)
	go s.handleSignals()

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

		// Open the SSH session for the connection, and track it in our sessions mapping
		session := NewSSHSession(s, sshConn)
		s.sessions[session.UUID] = session

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

// TODO: close stuff cleanly
func (s *SSHDState) handleSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)

	go func() {
		for {
			sig := <-signals

			if sig == syscall.SIGHUP {
				s.log.Info("Reloading accounts")
				s.reloadAccounts()
			}
		}
	}()
}
