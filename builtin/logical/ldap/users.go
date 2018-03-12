package ldap

import "github.com/hashicorp/vault/logical/framework"

func newUserRequestHandler() *userRequestHandler {
	return &userRequestHandler{}
}

type userRequestHandler struct{}

func (h *userRequestHandler) Handle() *framework.Path {
	// TODO
	return nil
}
