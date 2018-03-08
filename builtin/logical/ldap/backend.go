package ldap

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	// so this is hit right when you do
	// `$ vault secrets enable ldap`
	// because the factory is registered under its name of 'ldap'
	// in commands.go
	return NewBackend(), nil
}

func NewBackend() logical.Backend {

	confHandler := newConfigurationHandler()

	return &framework.Backend{
		Help: "TODO",
		Paths: []*framework.Path{
			confHandler.Handle(),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				confHandler.Path(),
			},
		},
		BackendType: logical.TypeLogical,
	}
}
