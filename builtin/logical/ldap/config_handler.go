package ldap

import (
	"context"
	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/helper/ldap"
)

func newConfigurationHandler() ConfigurationHandler {
	return &configurationHandler{}
}

type ConfigurationHandler interface {
	Path() string
	Handle() *framework.Path
}

type configurationHandler struct{}

func (h *configurationHandler) Path() string {
	return "config"
}

func (h *configurationHandler) Handle() *framework.Path {
	return &framework.Path{
		Pattern: h.Path(),
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:        framework.TypeString,
				Default:     "ldap://127.0.0.1",
				Description: "LDAP URL to connect to (default: ldap://127.0.0.1). Multiple URLs can be specified by concatenating them with commas; they will be tried in-order.",
			},

			"userdn": {
				Type:        framework.TypeString,
				Description: "LDAP domain to use for users (eg: ou=People,dc=example,dc=org)",
			},

			"binddn": {
				Type:        framework.TypeString,
				Description: "LDAP DN for searching for the user DN (optional)",
			},

			"bindpass": {
				Type:        framework.TypeString,
				Description: "LDAP password for searching for the user DN (optional)",
			},

			"groupdn": {
				Type:        framework.TypeString,
				Description: "LDAP search base to use for group membership search (eg: ou=Groups,dc=example,dc=org)",
			},

			"groupfilter": {
				Type:    framework.TypeString,
				Default: "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))",
				Description: `Go template for querying group membership of user (optional)
The template can access the following context variables: UserDN, Username
Example: (&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))
Default: (|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))`,
			},

			"groupattr": {
				Type:    framework.TypeString,
				Default: "cn",
				Description: `LDAP attribute to follow on objects returned by <groupfilter>
in order to enumerate user group membership.
Examples: "cn" or "memberOf", etc.
Default: cn`,
			},

			"upndomain": {
				Type:        framework.TypeString,
				Description: "Enables userPrincipalDomain login with [username]@UPNDomain (optional)",
			},

			"userattr": {
				Type:        framework.TypeString,
				Default:     "cn",
				Description: "Attribute used for users (default: cn)",
			},

			"certificate": {
				Type:        framework.TypeString,
				Description: "CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded (optional)",
			},

			"discoverdn": {
				Type:        framework.TypeBool,
				Description: "Use anonymous bind to discover the bind DN of a user (optional)",
			},

			"insecure_tls": {
				Type:        framework.TypeBool,
				Description: "Skip LDAP server SSL Certificate verification - VERY insecure (optional)",
			},

			"starttls": {
				Type:        framework.TypeBool,
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

			"deny_null_bind": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Denies an unauthenticated LDAP bind request if the user's password is empty; defaults to true",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   h.handleReadOperation,
			logical.UpdateOperation: h.handleUpdateOperation,
		},
		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (h *configurationHandler) handleReadOperation(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {

	entry, err := req.Storage.Get(ctx, h.Path())
	if err != nil {
		return nil, err
	}

	ldapClientConf := &ldap.Configuration{}
	if err := entry.DecodeJSON(ldapClientConf); err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: structs.New(ldapClientConf).Map(),
	}
	resp.AddWarning("Read access to this endpoint should be controlled via ACLs as it will return the configuration information as-is, including any passwords.")
	return resp, nil
}

func (h *configurationHandler) handleUpdateOperation(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {

	ldapClientConf, err := ldap.NewConfiguration(fieldData)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	entry, err := logical.StorageEntryJSON(h.Path(), ldapClientConf)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

const pathConfigHelpSyn = `
Configure the LDAP server to connect to, along with its options.
`

const pathConfigHelpDesc = `
This endpoint allows you to configure the LDAP server to connect to and its
configuration options.

The LDAP URL can use either the "ldap://" or "ldaps://" schema. In the former
case, an unencrypted connection will be made with a default port of 389, unless
the "starttls" parameter is set to true, in which case TLS will be used. In the
latter case, a SSL connection will be established with a default port of 636.

## A NOTE ON ESCAPING

It is up to the administrator to provide properly escaped DNs. This includes
the user DN, bind DN for search, and so on.

The only DN escaping performed by this backend is on usernames given at login
time when they are inserted into the final bind DN, and uses escaping rules
defined in RFC 4514.

Additionally, Active Directory has escaping rules that differ slightly from the
RFC; in particular it requires escaping of '#' regardless of position in the DN
(the RFC only requires it to be escaped when it is the first character), and
'=', which the RFC indicates can be escaped with a backslash, but does not
contain in its set of required escapes. If you are using Active Directory and
these appear in your usernames, please ensure that they are escaped, in
addition to being properly escaped in your configured DNs.

For reference, see https://www.ietf.org/rfc/rfc4514.txt and
http://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
`
