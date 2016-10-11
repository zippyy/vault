package database

import (
	"fmt"
	"strings"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	_ "github.com/lib/pq"
	_ "github.com/go-sql-driver/mysql"
)

func pathConfigConnection(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "dbs/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: `Database connection name`,
			},

			"database_type": {
				Type:        framework.TypeString,
				Description: `Database type (ex: postgres)`,
			},

            "options": {
                Type:     framework.TypeMap,
                Description: `Database specific options as described in the docs.`,
            },
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConnectionWrite,
			logical.ReadOperation:   b.pathConnectionRead,
		},

		HelpSynopsis:    pathConfigConnectionHelpSyn,
		HelpDescription: pathConfigConnectionHelpDesc,
	}
}

// pathConnectionRead reads out the connection configuration
func (b *backend) pathConnectionRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	entry, err := req.Storage.Get("dbs/"+name)
	if err != nil {
		return nil, fmt.Errorf("failed to read connection configuration")
	}
	if entry == nil {
		return nil, nil
	}

    // add building the config
	
	return &logical.Response{
		Data: structs.New(entry).Map(),
	}, nil
}

func (b *backend) pathConnectionWrite(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.logger.Trace("[TRACE] db/pathConnectionWrite: enter")
	defer b.logger.Trace("[TRACE] db/pathConnectionWrite: exit")
	dbName := data.Get("name").(string)
	
	b.dbs[dbName] = nil
	
	// Get the database type
	dbType := strings.ToLower(data.Get("database_type").(string))
	if dbType == "" {
		return logical.ErrorResponse("database_type parameter must be supplied"), nil
	}
    
    options := data.Get("options").(map[string]interface{})
    dbOptions := make(map[string]string)
    for k, v := range options {
        vStr, ok := v.(string)
        if !ok {
            return logical.ErrorResponse("options must be string valued"),
                logical.ErrInvalidRequest
        }
        dbOptions[k] = vStr
    }
    
	switch dbType {
	case "postgres":
        var config configPostgres
		err := buildPostgres(dbOptions, &config)
	case "mysql":
        var config configMySQL
        err := buildMySQL(dbOptions, &config)
    case "mssql":
        var config configMSSQL
        err := buildMSSQL(dbOptions, &config)
	default:
		return logical.ErrorResponse(fmt.Sprintf(
			"Error validating connection info: unrecognized database type")), nil
	}
    
    if err != nil {
        return logical.ErrorResponse(fmt.Sprintf(
			"Error validating connection info: %v"), err), nil
    }

	// Store it
	entry, err := logical.StorageEntryJSON("dbs/"+dbName, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}
	
	//Reset the DB connection
	b.ResetDB(dbName)

	resp := &logical.Response{}
	resp.AddWarning("Read access to this endpoint should be controlled via ACLs as it will return the connection string or URL as it is, including passwords, if any.")

	return resp, nil
}

const pathConfigConnectionHelpSyn = `
Configure the connection string to talk to PostgreSQL.
`

const pathConfigConnectionHelpDesc = `
This path configures the connection string used to connect to PostgreSQL.
The value of the string can be a URL, or a PG style string in the
format of "user=foo host=bar" etc.

The URL looks like:
"postgresql://user:pass@host:port/dbname"

When configuring the connection string, the backend will verify its validity.
`
