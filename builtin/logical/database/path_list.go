package database

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	_ "github.com/lib/pq"
)

// This returns the list of databases
func pathListDBs(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sql/dbs/",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathDBsList,
		},

		HelpSynopsis:    pathListHelpSyn,
		HelpDescription: pathListHelpDesc,
	}
}

func (b *backend) pathDBsList(req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	entries, err := req.Storage.List("sql/dbs/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const pathListHelpSyn = `
List the databases.
`

const pathListHelpDesc = `
This allows the databases to be listed.
`