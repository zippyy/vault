package database

import (
	"database/sql"
//	"strings"
	"fmt"

	_ "github.com/lib/pq"
)

type SqlDb struct {
	config     *SqlConfig
	connection *sql.DB
}

type SqlConfig struct {
	// Database type
	DBType string `json:"database_type" structs:"database_type" mapstructure:"database_type"`

	// The connection string for reaching the database
	ConnectionString string `json:"connection_string" structs:"connection_string" mapstructure:"connection_string"`

	// Maximum number of open connections
	MaxOpenConnections int `json:"max_open_connections" structs:"max_open_connections" mapstructure:"max_open_connections"`

	// Maximum number of idle connections
	MaxIdleConnections int `json:"max_idle_connections" structs:"max_idle_connections" mapstructure:"max_idle_connections"`

	// Allowed roles for this database
	AllowedRoles string `json:"allowed_roles" structs:"allowed_roles" mapstructure:"allowed_roles"`
}

func verifyConnection(dbType string, connstr string) string {
	connect, err := sql.Open(dbType, connstr)
	if err != nil {
		return fmt.Sprintf("Error validating connection info: %s", err)
	}
	defer connect.Close()
	if err := connect.Ping(); err != nil {
		return fmt.Sprintf("Error validating connection info: %s", err)
	}
	return ""
}

/*
func DBConnect(db *SqlDb) error {
	// If the connection exists, move on
	if db.connection != nil {
		if err := db.connection.Ping(); err == nil {
			return nil
		}
		// If the ping was unsuccessful, close it and ignore errors
		// in favor of attempting to reestablish the connection
		db.connection.Close()
	}

	connstr := db.config.ConnectionString
	sqltype := db.config.DBType

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

	dbconn, err := sql.Open(sqltype, connstr)
	if err != nil {
		return err
	}
	
	db.connection = dbconn

	// Set the connection pool settings based on settings.
	db.connection.SetMaxOpenConns(db.config.MaxOpenConnections)
	db.connection.SetMaxIdleConns(db.config.MaxIdleConnections)

	return nil
}

// ResetDB forces a connection on the next call to DBConnection()
func (b *backend) ResetDB(name string) {
	b.logger.Trace("db/resetdb: enter")
	defer b.logger.Trace("db/resetdb: exit")

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.dbs[name].connection != nil {
		b.dbs[name].connection.Close()
	}

	b.dbs[name].connection = nil
}
*/