package database

import (
	"database/sql"
	"fmt"
    "time"
    "strconv"

	_ "github.com/go-sql-driver/mysql"
)

func buildMySQL(options map[string]string, db *configMySQL) (error) {
	connStr := options["connection_string"]
	if connStr == "" {
		return fmt.Errorf("connection_string parameter must be supplied")
	}

    var maxOpenConns int
	maxOpenConnsStr := options["max_open_connections"]
	if maxOpenConnsStr == "" {
		maxOpenConns := 2
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
        err = verifyConnection("mysql", connStr)
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

func (config configMySQL) Connect(dbConn *sql.DB) (error) {
	// If the connection exists, move on
	if dbConn != nil {
		if err := dbConn.Ping(); err == nil {
			return nil
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

type configConnectMySQL struct {
	config configMySQL
	connection *sql.DB
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
	CreationSQL        string        `json:"creation_sql" mapstructure:"creation_sql" structs:"creation_sql"`
	RevocationSQL      string        `json:"revocation_sql" mapstructure:"revocation_sql" structs:"revocation_sql"`
	RollbackSQL        string        `json:"rollback_sql" mapstructure:"rollback_sql" structs:"rollback_sql"`
    ConnectionTemplate bool          `json:"connection_template" mapstructure:"connection_template" structs:"connection_template"`
    DefaultTTL         time.Duration `json:"default_ttl" mapstructure:"default_ttl" structs:"default_ttl"`
    MaxTTL             time.Duration `json:"max_ttl" mapstructure:"max_ttl" structs:"max_ttl"` 
	UsernameLength     int           `json:"username_length" mapstructure:"username_length" structs:"username_length"`
	DisplaynameLength  int           `json:"displayname_length" mapstructure:"displayname_length" structs:"displayname_length"`
	RolenameLength     int           `json:"rolename_length" mapstructure:"rolename_length" structs:"rolename_length"`
}