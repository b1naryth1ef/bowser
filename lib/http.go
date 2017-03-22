package bowser

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
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
	auth := r.Header.Get("Authorization")

	for _, key := range s.sshd.Config.HTTPServer.APIKeys {
		if key == auth {
			return true
		}
	}

	return false
}

type JSONSession struct {
	UUID        string   `json:"uuid"`
	Username    string   `json:"username"`
	Version     string   `json:"version"`
	ClientAddr  string   `json:"client-addr"`
	Connections []string `json:"connections"`
}

func SessionToJSONSession(sshSession *SSHSession) JSONSession {
	session := JSONSession{
		UUID:       sshSession.UUID,
		Username:   sshSession.Account.Username,
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
