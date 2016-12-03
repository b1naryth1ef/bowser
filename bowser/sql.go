package bowser

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

var baseSchema = `
CREATE TABLE IF NOT EXISTS login_attempts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT,
	remote_host TEXT,
	local_host TEXT,
	ssh_version TEXT,
	timestamp DATETIME
);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	login INTEGER,
	started DATETIME,
	ended DATETIME,
	FOREIGN KEY(login) REFERENCES login_attempts(id)
);
`

type Database struct {
	db *sql.DB

	loginAttemptSQL *sql.Stmt
	sessionSQL      *sql.Stmt
	endSessionSQL   *sql.Stmt
}

func NewDatabase(path string) (*Database, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	result := &Database{
		db: db,
	}

	result.init()
	return result, nil
}

func (db *Database) init() {
	_, err := db.db.Exec(baseSchema)
	if err != nil {
		log.Printf("error creating base schmea: %v", err)
	}

	db.loginAttemptSQL, err = db.db.Prepare(`
		INSERT INTO login_attempts (
			username, remote_host, local_host, ssh_version, timestamp
		) VALUES (
			?, ?, ?, ?, datetime('now')
		);
	`)

	db.sessionSQL, _ = db.db.Prepare(`
		INSERT INTO sessions (
			id, login, started, ended
		) VALUES (
			?, ?, datetime('now'), null
		);
	`)

	db.endSessionSQL, _ = db.db.Prepare(`
		UPDATE sessions
		SET ended=datetime('now')
		WHERE id=?
	`)
}

func (db *Database) insertLoginAttempt(s *SSHSession) int64 {
	res, _ := db.loginAttemptSQL.Exec(
		s.Account.Username,
		s.Conn.RemoteAddr().String(),
		s.Conn.LocalAddr().String(),
		s.Conn.ClientVersion(),
	)
	lastID, _ := res.LastInsertId()
	return lastID
}

func (db *Database) insertSession(uuid string, login int64) {
	db.sessionSQL.Exec(uuid, login)
}

func (db *Database) endSession(uuid string) {
	db.endSessionSQL.Exec(uuid)
}
