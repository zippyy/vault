package database

import (
	"database/sql"
	"fmt"
    "time"
    "strconv"

	_ "github.com/lib/pq"
)

func buildMSSQL(options map[string]string, db *configMSSQL) (error) {
	connStr := options["connection_string"]
	if connStr == "" {
		return fmt.Errorf("connection_string parameter must be supplied")
	}

    var maxOpenConns int
	maxOpenConnsStr := options["max_open_connections"]
	if maxOpenConnsStr == "" {
		maxOpenConns = 2
	} else {
        maxOpenConns, err := strconv.Atoi(maxOpenConnsStr)
        if err != nil {
            return fmt.Errorf("max_open_connections value cannot be parsed.")
        }
    }

    var maxIdleConns int
	maxIdleConnsStr := options["max_idle_connections"]
	if maxIdleConnsStr == "" {
		maxIdleConns = maxOpenConns
	} else {
        maxIdleConns, err := strconv.Atoi(maxIdleConnsStr)
        if err != nil {
            return fmt.Errorf("max_idle_connections value cannot be parsed.")
        }
    }
	if maxIdleConns > maxOpenConns {
		maxIdleConns = maxOpenConns
	}

	allowedRoles := options["allowed_roles"]

	// Don't check the connection_string if verification is disabled
	verifyConnStr := options["verify_connection"]
    verifyConn, err := strconv.ParseBool(verifyConnStr)
    if err != nil {
        return fmt.Errorf("verify_connection cannot be parsed.")
    }
	if verifyConn {
        err = verifyConnection("mssql", connStr)
        if err != nil {
            return err
        }
    }
    
	db.ConnectionString = connStr
	db.MaxOpenConnections = maxOpenConns
	db.MaxIdleConnections = maxIdleConns
	db.AllowedRoles	= allowedRoles
	
	return nil
}

func (connectInfo configConnectMSSQL) Connect() (error) {
	// If the connection exists, move on
	if connectInfo.connection != nil {
		if err := connectInfo.connection.Ping(); err == nil {
			return nil
		}
		// If the ping was unsuccessful, close it and ignore errors
		// in favor of attempting to reestablish the connection
		connectInfo.connection.Close()
	}

	dbConnNew, err := sql.Open("mssql", connectInfo.config.ConnectionString)
	if err != nil {
		connectInfo.connection = nil
		return err
	}
	
	// Set the connection pool settings based on settings.
	dbConnNew.SetMaxOpenConns(connectInfo.config.MaxOpenConnections)
	dbConnNew.SetMaxIdleConns(connectInfo.config.MaxIdleConnections)
	connectInfo.connection = dbConnNew
	
	return nil
}

func verifyConnection(dbType string, connstr string) error {
	connect, err := sql.Open(dbType, connstr)
	if err != nil {
		return fmt.Errorf("Error validating connection info: %s", err)
	}
	defer connect.Close()
	if err := connect.Ping(); err != nil {
		return fmt.Errorf("Error validating connection info: %s", err)
	}
	return nil
}

type configConnectMSSQL struct {
	config configMSSQL
	connection *sql.DB
}

type configMSSQL struct {
	// The connection string for reaching the database
	ConnectionString string `json:"connection_string" structs:"connection_string" mapstructure:"connection_string"`

	// Maximum number of open connections
	MaxOpenConnections int `json:"max_open_connections" structs:"max_open_connections" mapstructure:"max_open_connections"`

	// Maximum number of idle connections
	MaxIdleConnections int `json:"max_idle_connections" structs:"max_idle_connections" mapstructure:"max_idle_connections"`

	// Allowed roles for this database
	AllowedRoles string `json:"allowed_roles" structs:"allowed_roles" mapstructure:"allowed_roles"`
}

type roleEntryMSSQL struct {
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
    
    DefaultTTL         time.Duration `json:"default_ttl" mapstructure:"default_ttl" structs:"default_ttl"`
    MaxTTL             time.Duration `json:"max_ttl" mapstructure:"max_ttl" structs:"max_ttl"` 
}