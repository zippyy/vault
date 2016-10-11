package database

import (
)

type DatabaseOperations interface {
	Connect() error
    CloseConnection() error
    ResetConnect() error
    CreateUser() error
    RenewUser() error
    RevokeUser() error
}

type configDB struct {
    DatabaseType string `json:"database_type" mapstructure:"database_type" structs:"database_type"`
    ConfigInfo   []byte `json:"config_info" mapstructure:"config_info" structs:"config_info"`
    
}