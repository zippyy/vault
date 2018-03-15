package activedirectory

import "github.com/hashicorp/vault/logical/framework"

func newRoleRequestHandler() *roleRequestHandler {
	return &roleRequestHandler{}
}

// TODO remember that if you read and write any variables on these handlers,
// they will be used in a highly parallel fashion and will need a mutex.
// Avoid it if you can.
type roleRequestHandler struct{}

func (h *roleRequestHandler) Handle() *framework.Path {
	// TODO
	return nil
}
