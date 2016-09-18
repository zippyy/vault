package database

import (
//	"database/sql"
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

		//Clean: b.ResetDB,
	}

	b.logger = conf.Logger
	return &b
}

type backend struct {
	*framework.Backend

	lock sync.Mutex
	dbs  map[string]*SqlDb

	logger log.Logger
}

func (b *backend) DBConnection(s logical.Storage, name string) (error) {
	b.logger.Trace("sql/db: enter")
	defer b.logger.Trace("sql/db: exit")

	b.lock.Lock()
	defer b.lock.Unlock()

	// If don't have a database, error
	if b.dbs[name] == nil {
		// Attempt to find connection
		entry, err := s.Get("sql/db"+name)
		if err != nil {
			return err
		}
		if entry == nil {
			return fmt.Errorf("configure the DB connection with sql/db first")
		}
		
		if err := entry.DecodeJSON(&b.dbs[name].config); err == nil {
			return err
		}
	}
		return DBConnect(b.dbs[name])
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
