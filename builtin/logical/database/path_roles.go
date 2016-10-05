package database

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},

			"sql": {
				Type:        framework.TypeString,
				Description: "SQL string to create a user. See help for more info.",
			},
			
			"revoke_sql": {
				Type:        framework.TypeString,
				Description: "SQL string to revoke a user. See help for more info.",
			},
			
			"rollback_sql": {
				Type:        framework.TypeString,
				Description: "SQL string to rollback an errored user creation. See help for more info.",
			},
			
			"connection_template": {
				Type:        framework.TypeBool,
				Description: "allow the credential endpoint to emit a full connection template.",
				Default:     false,
			},

			"username_length": {
				Type:        framework.TypeInt,
				Description: "number of characters to truncate generated mysql usernames to (default 16)",
				Default:     16,
			},

			"rolename_length": {
				Type:        framework.TypeInt,
				Description: "number of characters to truncate the rolename portion of generated mysql usernames to (default 4)",
				Default:     4,
			},

			"displayname_length": {
				Type:        framework.TypeInt,
				Description: "number of characters to truncate the displayname portion of generated mysql usernames to (default 4)",
				Default:     4,
			},
			
			"database_name": {
				Type:        framework.TypeString,
				Description: "Name of the database associated with the role.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathRoleRead,
			logical.UpdateOperation: b.pathRoleCreate,
			logical.DeleteOperation: b.pathRoleDelete,
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func (b *backend) Role(s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get("role/" + n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathRoleDelete(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete("role/" + data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.Role(req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"database_name":       role.DBName,
			"sql":                 role.SQL,
			"revoke_sql":          role.RevokeSQL,
			"rollback_sql":        role.RollbackSQL,
			"connection_template": role.ConnectionTemplate,
		},
	}, nil
}

func (b *backend) pathRoleList(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List("role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRoleCreate(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	sqlstmt := data.Get("sql").(string)
	db_name := data.Get("database_name").(string)
	
	// Get our connection
	dbconn, err := b.DBConnection(req.Storage, db_name)
	if dbconn == nil {
		b.logger.Trace("[TRACE] b.dbs[%s] is not connected.", db_name)
		return nil, err
	}

	// Test the query by trying to prepare it
	for _, query := range strutil.ParseArbitraryStringSlice(sqlstmt, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}
		
		stmt, err := dbconn.Prepare(Query(query, map[string]string{
			"name":       "foo",
			"password":   "bar",
			"expiration": "",
		}))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf(
				"Error testing query: %s", err)), nil
		}
		stmt.Close()
	}

	// Store it
	entry, err := logical.StorageEntryJSON("role/"+name, &roleEntry{
		DBName:             db_name,
		SQL:                sqlstmt,
		RevokeSQL:          data.Get("revoke_sql").(string),
		RollbackSQL:        data.Get("rollback_sql").(string),
		ConnectionTemplate: data.Get("connection_template").(bool),
		UsernameLength:     data.Get("username_length").(int),
		DisplaynameLength:  data.Get("displayname_length").(int),
		RolenameLength:     data.Get("rolename_length").(int),
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type roleEntry struct {
	// Name of database that will use the role
	DBName             string `json:"database_name"`
	
	// SQL statement for the role
	SQL                string `json:"sql"`
	
	// SQL statement for revoking users
	RevokeSQL          string `json:"revoke_sql" mapstructure:"revoke_sql" structs:"revoke_sql"`
	
	// SQL statement for cleaning up after failing to add a user
	RollbackSQL        string `json:"rollback_sql" mapstructure:"rollback_sql" structs:"rollback_sql"`
	
	// Connection template should be allowed when credentials are issued
	ConnectionTemplate bool   `json:"connection_template" mapstructure:"connection_template" structs:"connection_template"`
	
	// Username length to truncate the generated name
	UsernameLength     int    `json:"username_length" mapstructure:"username_length" structs:"username_length"`
	
	// Display name length to truncate the generated name
	DisplaynameLength  int    `json:"displayname_length" mapstructure:"displayname_length" structs:"displayname_length"`
	
	// Role name length to truncate the generated name
	RolenameLength     int    `json:"rolename_length" mapstructure:"rolename_length" structs:"rolename_length"`
	
	
}

const pathRoleHelpSyn = `
Manage the roles that can be created with this backend.
`

const pathRoleHelpDesc = `
This path lets you manage the roles that can be created with this backend.

The "sql" parameter customizes the SQL string used to create the role.
This can be a sequence of SQL queries. Some substitution will be done to the
SQL string for certain keys. The names of the variables must be surrounded
by "{{" and "}}" to be replaced.

  * "name" - The random username generated for the DB user.

  * "password" - The random password generated for the DB user.

  * "expiration" - The timestamp when this user will expire.

Example of a decent SQL query to use:

	CREATE ROLE "{{name}}" WITH
	  LOGIN
	  PASSWORD '{{password}}'
	  VALID UNTIL '{{expiration}}';
	GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "{{name}}";

Note the above user would be able to access everything in schema public.
For more complex GRANT clauses, see the PostgreSQL manual.
`
