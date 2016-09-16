package database

import (
	"database/sql"
	"strings"
	"sync"

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
	dbs  map[string]*sql.DB

	logger log.Logger
}

type Database interface {
	DBConnection(logical.Storage, string)
	Lease(logical.Storage, string)
	ResetDB(string)
	CloseDB(string)
	CreateUser()
	RenewUser()
	RevokeUser()
}

const backendHelp = `
The database backend dynamically generates database users.

After mounting this backend, configure it using the endpoints within
the "config/" path.
`
