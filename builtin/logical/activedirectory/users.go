package activedirectory

import "github.com/hashicorp/vault/logical/framework"

func newUserRequestHandler() *userRequestHandler {
	return &userRequestHandler{}
}

// TODO remember that if you read and write any variables on these handlers,
// they will be used in a highly parallel fashion and will need a mutex.
// Avoid it if you can.
type userRequestHandler struct{}

func (h *userRequestHandler) Handle() *framework.Path {
	// TODO
	return nil
}
