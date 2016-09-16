package database

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/logical"
	_ "github.com/lib/pq"
)

func verifyConnection(connStr string) string {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Sprintf("Error validating connection info: %s", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Sprintf("Error validating connection info: %s", err)
	}
	return nil
}

func (b *backend) DBConnection(s logical.Storage, name string) (*sql.DB, error) {
	b.logger.Trace("sql/db: enter")
	defer b.logger.Trace("sql/db: exit")

	b.lock.Lock()
	defer b.lock.Unlock()

	// If we already have the DB, move on
	if b.dbs[name] != nil {
		if err := b.dbs[name].Ping(); err == nil {
			return b.dbs[name], nil
		}
		// If the ping was unsuccessful, close it and ignore errors
		// in favor of attempting to reestablish the connection
		b.dbs[name].Close()
	}

	// Attempt to make the connection
	entry, err := s.Get("config/connection/" + name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil,
			fmt.Errorf("configure the DB connection with config/connection first")
	}

	var connConfig connectionConfig
	if err := entry.DecodeJSON(&connConfig); err != nil {
		return nil, err
	}

	conn := connConfig.ConnectionString

	// Ensure UTC for all connections
	if strings.HasPrefix(conn, "postgres://") || strings.HasPrefix(conn, "postgresql://") {
		if strings.Contains(conn, "?") {
			conn += "&timezone=utc"
		} else {
			conn += "?timezone=utc"
		}
	} else {
		conn += " timezone=utc"
	}

	b.dbs[name], err = sql.Open("postgres", conn)
	if err != nil {
		return nil, err
	}

	// Set the connection pool settings based on settings.
	b.dbs[name].SetMaxOpenConns(connConfig.MaxOpenConnections)
	b.dbs[name].SetMaxIdleConns(connConfig.MaxIdleConnections)

	return b.db[name], nil
}

// ResetDB forces a connection on the next call to DBConnection()
func (b *backend) ResetDB(name string) {
	b.logger.Trace("postgres/resetdb: enter")
	defer b.logger.Trace("postgres/resetdb: exit")

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.dbs[name] != nil {
		b.dbs[name].Close()
	}

	b.dbs[name] = nil
}

// Lease returns lease information
func (b *backend) Lease(s logical.Storage) (*configLease, error) {
	entry, err := s.Get("config/lease")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result configLease
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Close the DB Connection
func (b *backend) CloseDB(name string) {
	if b.dbs[name] != nil {
		b.dbs[name].Close()
	}
}
