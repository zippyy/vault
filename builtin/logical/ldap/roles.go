package ldap

import "github.com/hashicorp/vault/logical/framework"

func newRoleRequestHandler() *roleRequestHandler {
	return &roleRequestHandler{}
}

type roleRequestHandler struct {}

func (h *roleRequestHandler) Handle() *framework.Path {
	// TODO
	return nil
}
