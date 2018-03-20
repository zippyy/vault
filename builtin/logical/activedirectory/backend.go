package activedirectory

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return &framework.Backend{
		Help: "kitties",
		Paths: []*framework.Path{
			pathConfig(),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		BackendType: logical.TypeLogical,
	}, nil
}
