package database

import (
	"database/sql"
	"fmt"

	"github.com/hashicorp/vault/logical/framework"
	_ "github.com/lib/pq"
)

func buildPostgres(data *framework.FieldData, db *configPostgres) (error) {
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
	err := verifyConnection(dbType, connStr)
	if err != "" {
		return err
	}
	
	db.DBType = dbType
	db.ConnectionString = connStr
	db.MaxOpenConnections = maxOpenConns
	db.MaxIdleConnections = maxIdleConns
	db.AllowedRoles	= allowedRoles
	
	return nil
}

func (config configPostgres) Connect(dbConn *sql.DB) (error) {
	// If the connection exists, move on
	if dbConn != nil {
		if err := dbConn.Ping(); err == nil {
			return dbConn, nil
		}
		// If the ping was unsuccessful, close it and ignore errors
		// in favor of attempting to reestablish the connection
		dbConn.Close()
	}

	// Ensure UTC for all connections
	if strings.HasPrefix(config.ConnectionString, "postgres://") || strings.HasPrefix(config.ConnectionString, "postgresql://") {
		if strings.Contains(config.ConnectionString, "?") {
			config.ConnectionString += "&timezone=utc"
		} else {
			config.ConnectionString += "?timezone=utc"
		}
	} else {
		config.ConnectionString += " timezone=utc"
	}

	dbConnNew, err := sql.Open(config.DBType, config.ConnectionString)
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

func verifyConnection(dbType string, connstr string) string {
	connect, err := sql.Open(dbType, connstr)
	if err != nil {
		return fmt.Sprintf("Error validating connection info: %s", err)
	}
	defer connect.Close()
	if err := connect.Ping(); err != nil {
		return fmt.Sprintf("Error validating connection info: %s", err)
	}
	return ""
}

type configPostgres struct {
	// The connection string for reaching the database
	ConnectionString string `json:"connection_string" structs:"connection_string" mapstructure:"connection_string"`

	// Maximum number of open connections
	MaxOpenConnections int `json:"max_open_connections" structs:"max_open_connections" mapstructure:"max_open_connections"`

	// Maximum number of idle connections
	MaxIdleConnections int `json:"max_idle_connections" structs:"max_idle_connections" mapstructure:"max_idle_connections"`

	// Allowed roles for this database
	AllowedRoles string `json:"allowed_roles" structs:"allowed_roles" mapstructure:"allowed_roles"`
}

type roleEntryPostgres struct {
	// Name of database that will use the role
	DBName             string `json:"database_name" mapstructure:"database_name" structs:"database_name"`
	
	// SQL statement for the role
	CreationSQL        string `json:"creation_sql" mapstructure:"creation_sql" structs:"creation_sql"`
	
	// SQL statement for revoking users
	RevocationSQL      string `json:"revoke_sql" mapstructure:"revoke_sql" structs:"revoke_sql"`
	
	// SQL statement for cleaning up after failing to add a user
	RollbackSQL        string `json:"rollback_sql" mapstructure:"rollback_sql" structs:"rollback_sql"`
	
	// Connection template should be allowed when credentials are issued
	ConnectionTemplate bool   `json:"connection_template" mapstructure:"connection_template" structs:"connection_template"`
}