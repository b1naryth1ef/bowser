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
	log.Fatal(http.ListenAndServe(s.sshd.Config.HTTPServer.Bind, s.router))
}

func (s *HTTPServer) registerRoutes() {
	s.router.HandleFunc("/sessions", s.GetSessions)
	s.router.HandleFunc("/sessions/{uuid}", s.EndSession).Methods("DELETE")
}

type JSONSession struct {
	UUID        string   `json:"uuid"`
	Username    string   `json:"username"`
	ClientAddr  string   `json:"client-addr"`
	Connections []string `json:"connections"`
}

func (s *HTTPServer) GetSessions(w http.ResponseWriter, r *http.Request) {
	var sessions []JSONSession

	for _, sshSession := range s.sshd.sessions {
		session := JSONSession{
			UUID:       sshSession.UUID,
			Username:   sshSession.Account.Username,
			ClientAddr: sshSession.Conn.RemoteAddr().String(),
		}

		for _, conn := range sshSession.Proxies {
			session.Connections = append(session.Connections, conn.LocalAddr().String())
		}

		sessions = append(sessions, session)
	}

	json.NewEncoder(w).Encode(sessions)
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
