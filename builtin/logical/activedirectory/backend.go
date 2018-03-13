package activedirectory

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {

	// DRAFT OF API ENDPOINTS
	//
	// Method     Path             Requirement
	//
	// LIST       /ldap/users      Lists users to get their ID for managing them - but could this be thousands of people?
	// GET        /ldap/user/:id   Reads a user by ID
	// PUT        /ldap/user       Use the post body to update their name, pass, or group
	//
	// LIST       /ldap/roles      Lists all roles to help manage them
	// PUT        /ldap/role/:id   Edit an existing role
	//
	// GET        /ldap/creds      Fetches a new credential

	confHandler := newConfigurationRequestHandler()
	userHandler := newUserRequestHandler()
	roleHandler := newRoleRequestHandler()

	return &framework.Backend{
		Help: "TODO",
		Paths: []*framework.Path{
			confHandler.Handle(),
			userHandler.Handle(),
			roleHandler.Handle(),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				confHandler.Path(),
			},
		},
		BackendType: logical.TypeLogical,
	}, nil
}
