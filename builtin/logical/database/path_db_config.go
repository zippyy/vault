package database

import (
	"fmt"
	"strings"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	_ "github.com/lib/pq"
)

func pathConfigConnection(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "dbs/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Database connection name`,
			},

			"database_type": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Database type (ex: postgres)`,
			},

			"connection_string": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Database connection string`,
			},

			"verify_connection": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Default:     true,
				Description: `If set, connection_string is verified by actually connecting to the database`,
			},

			"max_open_connections": &framework.FieldSchema{
				Type: framework.TypeInt,
				Description: `Maximum number of open connections to the database;
a zero uses the default value of two and a
negative value means unlimited`,
			},

			"max_idle_connections": &framework.FieldSchema{
				Type: framework.TypeInt,
				Description: `Maximum number of idle connections to the database;
a zero uses the value of max_open_connections
and a negative value disables idle connections.
If larger than max_open_connections it will be
reduced to the same size.`,
			},

			"allowed_roles": &framework.FieldSchema{
				Type:    framework.TypeString,
				Default: "",
				Description: `Comma separated list of roles allowed for the database.
When no value is given, no roles are allowed. When * is given, all roles are allowed.`,
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

	var config SqlConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: structs.New(config).Map(),
	}, nil
}

func (b *backend) pathConnectionWrite(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dbName := data.Get("name").(string)
	
	connStr := data.Get("connection_string").(string)
	if connStr == "" {
		return logical.ErrorResponse("connection_string parameter must be supplied"), nil
	}

	maxOpenConns := data.Get("max_open_connections").(int)
	if maxOpenConns == 0 {
		maxOpenConns = 2
	}

	maxIdleConns := data.Get("max_idle_connections").(int)
	if maxIdleConns == 0 {
		maxIdleConns = maxOpenConns
	}
	if maxIdleConns > maxOpenConns {
		maxIdleConns = maxOpenConns
	}

	// Get the database type before attempting to verify the connection
	dbType := strings.ToLower(data.Get("database_type").(string))
	if dbType == "" {
		return logical.ErrorResponse("database_type parameter must be supplied"), nil
	}

	allowedRoles := data.Get("allowed_roles").(string)

	// Don't check the connection_string if verification is disabled
	verifyConn := data.Get("verify_connection").(bool)
	if verifyConn {
		// Verify the string
		switch dbType {
		case "postgres":
			err := verifyConnection(dbType, connStr)
			if err != "" {
				return logical.ErrorResponse(err), nil
			}
		default:
			return logical.ErrorResponse(fmt.Sprintf(
				"Error validating connection info: unrecognized database type")), nil
		}
	}

	// Store it
	entry, err := logical.StorageEntryJSON("dbs/"+dbName, SqlConfig{
		DBType:             dbType,
		ConnectionString:   connStr,
		MaxOpenConnections: maxOpenConns,
		MaxIdleConnections: maxIdleConns,
		AllowedRoles:       allowedRoles,
	})
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
