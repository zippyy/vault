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
		Pattern: "config/connection",
		Fields: map[string]*framework.FieldSchema{
			"database_name": &framework.FieldSchema{
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
	entry, err := req.Storage.Get("config/connection")
	if err != nil {
		return nil, fmt.Errorf("failed to read connection configuration")
	}
	if entry == nil {
		return nil, nil
	}

	var config connectionConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: structs.New(config).Map(),
	}, nil
}

func (b *backend) pathConnectionWrite(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

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

	dbName := data.Get("database_name").(string)
	if dbName == "" {
		return logical.ErrorResponse("database_name parameter must be supplied"), nil
	}

	// Don't check the connection_string if verification is disabled
	verifyConn := data.Get("verify_connection").(bool)
	if verifyConn {
		// Verify the string
		switch dbType {
		case "postgres":
			err := verifyConnection(connStr)
			if err != "" {
				return logical.ErrorResponse(err), nil
			}
		default:
			return logical.ErrorResponse(fmt.Sprintf(
				"Error validating connection info: unrecognized database type")), nil
		}
	}

	// Store it
	entry, err := logical.StorageEntryJSON("config/connection", connectionConfig{
		DatabaseType:       dbType,
		DatabaseName:       dbName,
		ConnectionString:   connStr,
		MaxOpenConnections: maxOpenConns,
		MaxIdleConnections: maxIdleConns,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	resp := &logical.Response{}
	resp.AddWarning("Read access to this endpoint should be controlled via ACLs as it will return the connection string or URL as it is, including passwords, if any.")

	return resp, nil
}

type connectionConfig struct {
	DatabaseName       string `json:"database_name" structs: "database_name" mapstructure:"database_name"`
	DatabaseType       string `json:"database_type" structs:"database_type" mapstructure:"database_type"`
	ConnectionString   string `json:"connection_string" structs:"connection_string" mapstructure:"connection_string"`
	MaxOpenConnections int    `json:"max_open_connections" structs:"max_open_connections" mapstructure:"max_open_connections"`
	MaxIdleConnections int    `json:"max_idle_connections" structs:"max_idle_connections" mapstructure:"max_idle_connections"`
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
