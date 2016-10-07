package database

import (
	"database/sql"
	"fmt"

	"github.com/hashicorp/vault/logical/framework"
	_ "github.com/go-sql-driver/mysql"
)

func buildMySQL(data *framework.FieldData, db *configMySQL) (error) {
	connStr := data.Get("connection_string").(string)
	if connStr == "" {
		return fmt.Errorf("connection_string parameter must be supplied")
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

	allowedRoles := data.Get("allowed_roles").(string)

	// Don't check the connection_string if verification is disabled
	verifyConn := data.Get("verify_connection").(bool)
	err := verifyConnection("mysql", connStr)
	if err != "" {
		return fmt.Errorf("%v", err)
	}
	
	db.ConnectionString = connStr
	db.MaxOpenConnections = maxOpenConns
	db.MaxIdleConnections = maxIdleConns
	db.AllowedRoles	= allowedRoles
	
	return nil
}

func (config configMySQL) Connect(dbConn *sql.DB) (error) {
	// If the connection exists, move on
	if dbConn != nil {
		if err := dbConn.Ping(); err == nil {
			return dbConn, nil
		}
		// If the ping was unsuccessful, close it and ignore errors
		// in favor of attempting to reestablish the connection
		dbConn.Close()
	}

	dbConnNew, err := sql.Open("mysql", config.ConnectionString)
	if err != nil {
		dbConn = nil
		return err
	}
	
	// Set the connection pool settings based on settings.
	dbConnNew.SetMaxOpenConns(config.MaxOpenConnections)
	dbConnNew.SetMaxIdleConns(config.MaxIdleConnections)
	dbConn = dbConnNew
	
	return nil
}

type configMySQL struct {
	// The connection string for reaching the database
	ConnectionString string `json:"connection_string" structs:"connection_string" mapstructure:"connection_string"`

	// Maximum number of open connections
	MaxOpenConnections int `json:"max_open_connections" structs:"max_open_connections" mapstructure:"max_open_connections"`

	// Maximum number of idle connections
	MaxIdleConnections int `json:"max_idle_connections" structs:"max_idle_connections" mapstructure:"max_idle_connections"`

	// Allowed roles for this database
	AllowedRoles string `json:"allowed_roles" structs:"allowed_roles" mapstructure:"allowed_roles"`
}

type roleEntryMySQL struct {
	CreationSQL       string `json:"creation_sql" mapstructure:"creation_sql" structs:"creation_sql"`
	RevocationSQL     string `json:"revocation_sql" mapstructure:"revocation_sql" structs:"revocation_sql"`
	RollbackSQL       string `json:"rollback_sql" mapstructure:"rollback_sql" structs:"rollback_sql"`
	UsernameLength    int    `json:"username_length" mapstructure:"username_length" structs:"username_length"`
	DisplaynameLength int    `json:"displayname_length" mapstructure:"displayname_length" structs:"displayname_length"`
	RolenameLength    int    `json:"rolename_length" mapstructure:"rolename_length" structs:"rolename_length"`
}