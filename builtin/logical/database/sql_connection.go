package database

import (
	"database/sql"
	"strings"

	_ "github.com/lib/pq"
)

//type Database interface {
//	DBConnect(logical.Storage)
//	ResetDB(string)
//	CloseDB(string)
//	CreateUser()
//	RenewUser()
//	RevokeUser()
//}

type SqlDb struct {
	config     *SqlConfig
	connection *sql.DB
}

type SqlConfig struct {
	// Database type
	DBType string `json:"db_tyype"`

	// The connection string for reaching the database
	ConnectionString string `json:"connection_string"`

	// Maximum number of open connections
	MaxOpenConnections int `json:"max_open_connections"`

	// Maximum number of idle connections
	MaxIdleConnections int `json:"max_idle_connections"`

	// Allowed roles for this database
	AllowedRoles string `json:"allowed_roles"`
}

func DBConnect(db *SqlDb) error {
	// If the connection exists, move on
	if err := db.connection.Ping(); err == nil {
		return nil
	}
	// If the ping was unsuccessful, close it and ignore errors
	// in favor of attempting to reestablish the connection
	db.connection.Close()

	connstr := db.config.ConnectionString

	// Ensure UTC for all connections
	if strings.HasPrefix(connstr, "postgres://") || strings.HasPrefix(connstr, "postgresql://") {
		if strings.Contains(connstr, "?") {
			connstr += "&timezone=utc"
		} else {
			connstr += "?timezone=utc"
		}
	} else {
		connstr += " timezone=utc"
	}

	dbconn, err := sql.Open("postgres", connstr)
	if err != nil {
		return err
	}

	// Set the connection pool settings based on settings.
	dbconn.SetMaxOpenConns(db.config.MaxOpenConnections)
	dbconn.SetMaxIdleConns(db.config.MaxIdleConnections)

	return nil
}
