package ldap

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {

	confHandler := newConfigurationHandler()

	// TODO rotating a password is a requirement
	// In PKI, the way you rotate a CRL is this:
	// GET 	/pki/crl/rotate 	200 application/json
	// So maybe it would be similar to that
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
	}, nil
}
