package bowser

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
)

type HTTPServer struct {
	sshd   *SSHDState
	router *mux.Router
}

func NewHTTPServer(sshd *SSHDState) *HTTPServer {
	server := &HTTPServer{
		sshd:   sshd,
		router: mux.NewRouter().StrictSlash(true),
	}

	server.registerRoutes()
	return server
}

func (s *HTTPServer) Run() {
	log.Fatal(http.ListenAndServe(s.sshd.Config.HTTPServer.Bind, s))
}

func (s *HTTPServer) registerRoutes() {
	s.router.HandleFunc("/sessions", s.GetSessions)
	s.router.HandleFunc("/sessions/find/{conn}", s.FindSession)
	s.router.HandleFunc("/sessions/{uuid}", s.EndSession).Methods("DELETE")
	s.router.HandleFunc("/sessions/{uuid}/jump", s.SessionJump).Methods("POST")
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorized(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	s.router.ServeHTTP(w, r)
	return
}

func (s *HTTPServer) isAuthorized(r *http.Request) bool {
	// First, check if we have an auth header which matches any API keys
	auth := r.Header.Get("Authorization")
	for _, key := range s.sshd.Config.HTTPServer.APIKeys {
		if key == auth {
			return true
		}
	}

	// Otherwise, try to authenticate w/ our custom SSH agent auth
	sshAuthSignature, err := base64.StdEncoding.DecodeString(r.Header.Get("SSH-Auth-Signature"))
	if err != nil {
		return false
	}

	sshAuthKey := r.Header.Get("SSH-Auth-Key")
	sshAuthConnection := r.Header.Get("SSH-Auth-Connection")
	sshAuthTimestamp := r.Header.Get("SSH-Auth-Timestamp")

	if len(sshAuthSignature) <= 0 || sshAuthKey == "" || sshAuthConnection == "" || sshAuthTimestamp == "" {
		return false
	}

	// Attempt to find the given session
	var foundSession *SSHSession
	for _, sshSession := range s.sshd.sessions {
		for _, conn := range sshSession.Proxies {
			if sshAuthConnection == conn.LocalAddr().String() {
				foundSession = sshSession
				break
			}
		}
	}

	if foundSession == nil {
		return false
	}

	// Now grab all the keys for the session
	keys, err := foundSession.Agent.List()
	if err != nil {
		return false
	}

	timestamp, err := strconv.Atoi(sshAuthTimestamp)
	if err != nil {
		return false
	}

	// Timestamp should not be more than 10 seconds
	diff := timestamp - int(time.Now().Unix())
	if diff < 0 || diff > 10 {
		return false
	}
	// todo validate timestamp

	// Find the key used to sign the signature, and verify it
	for _, key := range keys {
		if key.String() == sshAuthKey {
			err = key.Verify([]byte(sshAuthTimestamp), &ssh.Signature{
				Format: "ssh-rsa",
				Blob:   sshAuthSignature,
			})

			if err == nil {
				return true
			}
		}
	}

	return false
}

type JSONSession struct {
	UUID        string                 `json:"uuid"`
	Username    string                 `json:"username"`
	SSHKeys     []string               `json:"ssh_keys"`
	Metadata    map[string]interface{} `json:"metadata"`
	Version     string                 `json:"version"`
	ClientAddr  string                 `json:"client-addr"`
	Connections []string               `json:"connections"`
}

func SessionToJSONSession(sshSession *SSHSession) JSONSession {
	session := JSONSession{
		UUID:       sshSession.UUID,
		Username:   sshSession.Account.Username,
		SSHKeys:    sshSession.Account.SSHKeysRaw,
		Metadata:   sshSession.Account.Metadata,
		Version:    string(sshSession.Conn.ClientVersion()),
		ClientAddr: sshSession.Conn.RemoteAddr().String(),
	}

	for _, conn := range sshSession.Proxies {
		session.Connections = append(session.Connections, conn.LocalAddr().String())
	}

	return session
}

func (s *HTTPServer) GetSessions(w http.ResponseWriter, r *http.Request) {
	var sessions []JSONSession

	for _, sshSession := range s.sshd.sessions {
		sessions = append(sessions, SessionToJSONSession(sshSession))
	}

	json.NewEncoder(w).Encode(sessions)
}

func (s *HTTPServer) FindSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connQ := vars["conn"]

	for _, sshSession := range s.sshd.sessions {
		for _, conn := range sshSession.Proxies {
			if connQ == conn.LocalAddr().String() {
				json.NewEncoder(w).Encode(SessionToJSONSession(sshSession))
				return
			}
		}
	}

	http.NotFound(w, r)
}

func (s *HTTPServer) EndSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	if session, exists := s.sshd.sessions[vars["uuid"]]; exists {
		session.Close(r.URL.Query().Get("message"))
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.NotFound(w, r)
	}
}

// Jumps a session, adding a temp-key to the agent
func (s *HTTPServer) SessionJump(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	session, exists := s.sshd.sessions[vars["uuid"]]
	if !exists {
		http.NotFound(w, r)
		return
	}

	r.ParseForm()
	addr, exists := r.Form["destination"]
	if !exists {
		http.Error(w, "Invalid Destination", 400)
		return
	}

	// Validate the user can connect to this address
	if !session.canConnectTo(addr[0]) {
		http.Error(w, "Invalid Permissions", 403)
		return
	}

	err := session.addTempAuth(addr[0])
	if err != nil {
		http.Error(w, "Failed to generate or add ssh certificate", 500)
	}

	w.WriteHeader(http.StatusNoContent)
}
