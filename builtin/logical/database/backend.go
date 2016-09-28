package database

import (
	"database/sql"
	"strings"
	"sync"
	"fmt"

	log "github.com/mgutz/logxi/v1"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	return Backend(conf).Setup(conf)
}

func Backend(conf *logical.BackendConfig) *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		Paths: []*framework.Path{
			pathConfigConnection(&b),
			pathListDBs(&b),
			pathConfigLease(&b),
			pathListRoles(&b),
			pathRoles(&b),
			pathRoleCreate(&b),
		},

		Secrets: []*framework.Secret{
			secretCreds(&b),
		},

		//Clean: ResetDB,
	}

	b.logger = conf.Logger
	b.dbs = make(map[string]*sql.DB)
	
	return &b
}

type backend struct {
	*framework.Backend

	lock sync.Mutex
	dbs  map[string]*sql.DB

	logger log.Logger
}

func (b *backend) DBConnection(s logical.Storage, name string) (*sql.DB, error) {
	b.logger.Trace("db: enter")
	defer b.logger.Trace("db: exit")

	b.lock.Lock()
	defer b.lock.Unlock()

	var config SqlConfig
	
	// If don't have a database, error
	if b.dbs[name] == nil {
		// Attempt to find connection
		entry, err := s.Get("dbs/"+name)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, fmt.Errorf("configure the DB connection with dbs/<name> first")
		}
		if err := entry.DecodeJSON(&config); err == nil {
			return nil, err
		}
	}
	
	// If the connection exists, move on
	if b.dbs[name] != nil {
		if err := b.dbs[name].Ping(); err == nil {
			return b.dbs[name], nil
		}
		// If the ping was unsuccessful, close it and ignore errors
		// in favor of attempting to reestablish the connection
		b.dbs[name].Close()
	}

	// Ensure UTC for all connections
	if strings.HasPrefix(config.ConnectionString, "postgres://") || strings.HasPrefix(config.ConnectionString, "postgresql://") {
		if strings.Contains(config.ConnectionString, "?") {
			config.ConnectionString += "&timezone=utc"
		} else {
			config.ConnectionString += "?timezone=utc"
		}
	} else {
		config.ConnectionString += " timezone=utc"
	}

	dbconn, err := sql.Open(config.DBType, config.ConnectionString)
	if err != nil {
		return nil, err
	}
	
	b.dbs[name] = dbconn

	// Set the connection pool settings based on settings.
	b.dbs[name].SetMaxOpenConns(config.MaxOpenConnections)
	b.dbs[name].SetMaxIdleConns(config.MaxIdleConnections)
	
	return b.dbs[name], nil
}

// ResetDB forces a connection on the next call to DBConnection()
func (b *backend) ResetDB(name string) {
	b.logger.Trace("db/resetdb: enter")
	defer b.logger.Trace("db/resetdb: exit")

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.dbs[name] != nil {
		b.dbs[name].Close()
	}

	b.dbs[name] = nil
}


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

const backendHelp = `
The database backend dynamically generates database users.

After mounting this backend, configure it using the endpoints within
the "config/" path.
`
