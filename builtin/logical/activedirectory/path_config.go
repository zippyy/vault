package activedirectory

import (
	"context"
	"github.com/fatih/structs"

	"github.com/hashicorp/vault/helper/activedirectory"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "Username with sufficient permissions in Active Directory to administer passwords.",
			},


			"password": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "Password for username with sufficient permissions in Active Directory to administer passwords.",
			},


			"url": {
				Type:        framework.TypeString,
				Default:     "ldap://127.0.0.1",
				Description: "LDAP URL to connect to (default: ldap://127.0.0.1). Multiple URLs can be specified by concatenating them with commas; they will be tried in-order.",
			},

			"certificate": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded (optional)",
			},

			"insecure_tls": {
				Type:        framework.TypeBool,
				Default: false,
				Description: "Skip LDAP server SSL Certificate verification - VERY insecure (optional)",
			},

			"starttls": {
				Type:        framework.TypeBool,
				Default: true,
				Description: "Issue a StartTLS command after establishing unencrypted connection (optional)",
			},

			"tls_min_version": {
				Type:        framework.TypeString,
				Default:     "tls12",
				Description: "Minimum TLS version to use. Accepted values are 'tls10', 'tls11' or 'tls12'. Defaults to 'tls12'",
			},

			"tls_max_version": {
				Type:        framework.TypeString,
				Default:     "tls12",
				Description: "Maximum TLS version to use. Accepted values are 'tls10', 'tls11' or 'tls12'. Defaults to 'tls12'",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   handleReadOperation,
			logical.UpdateOperation: handleUpdateOperation,
		},
		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func handleReadOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {

	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	ldapClientConf := &activedirectory.Configuration{}
	if err := entry.DecodeJSON(ldapClientConf); err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: structs.New(ldapClientConf).Map(),
	}
	resp.AddWarning("Read access to this endpoint should be controlled via ACLs as it will return the configuration information as-is, including any passwords.")
	return resp, nil
}

func handleUpdateOperation(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {

	ldapClientConf, err := activedirectory.NewConfiguration(fieldData)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	entry, err := logical.StorageEntryJSON("config", ldapClientConf)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

const pathConfigHelpSyn = ``

const pathConfigHelpDesc = ``
