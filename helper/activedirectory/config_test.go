package activedirectory

import (
	"testing"

	"github.com/hashicorp/vault/logical/framework"
	"github.com/magiconair/properties/assert"
)

func TestCertificateValidation(t *testing.T) {

	// certificate should default to "" without error is doesn't exist
	fd := fieldDataWithSchema()
	config, err := NewConfiguration(fd)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.Equal(t, config.Certificate, "")

	// certificate should cause an error if a bad one is provided
	fd.Raw = map[string]interface{}{
		"certificate": "cats",
	}
	config, err = NewConfiguration(fd)
	if err == nil {
		t.Error("bad certificates should cause errors")
		t.FailNow()
	}

	// valid certificates should pass inspection
	fd.Raw = map[string]interface{}{
		"certificate": validCertificate,
	}
	config, err = NewConfiguration(fd)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

func TestTLSDefaultsTo12(t *testing.T) {
	fd := fieldDataWithSchema()
	config, err := NewConfiguration(fd)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.Equal(t, config.TLSMinVersion, uint16(771))
	assert.Equal(t, config.TLSMaxVersion, uint16(771))
}

func TestTLSSessionDefaultsToStarting(t *testing.T) {
	fd := fieldDataWithSchema()
	config, err := NewConfiguration(fd)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.Equal(t, config.StartTLS, true)
}

func TestTLSSessionDefaultsToSecure(t *testing.T) {
	fd := fieldDataWithSchema()
	config, err := NewConfiguration(fd)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.Equal(t, config.InsecureTLS, false)
}

func TestGetTLSConfigs(t *testing.T) {
	fd := fieldDataWithSchema()
	fd.Raw = map[string]interface{}{
		"url": "ldap://138.91.247.105",
	}
	config, err := NewConfiguration(fd)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	tlsConfigs, err := config.GetTLSConfigs()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.Equal(t, len(tlsConfigs), 1)
	for u, tlsConfig := range tlsConfigs {
		assert.Equal(t, u.String(), "ldap://138.91.247.105")
		assert.Equal(t, tlsConfig.InsecureSkipVerify, false)
		assert.Equal(t, tlsConfig.ServerName, "138.91.247.105")
		assert.Equal(t, tlsConfig.MinVersion, uint16(771))
		assert.Equal(t, tlsConfig.MaxVersion, uint16(771))
	}
}

func fieldDataWithSchema() *framework.FieldData {
	return &framework.FieldData{
		Schema: map[string]*framework.FieldSchema{
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
				Default:     false,
				Description: "Skip LDAP server SSL Certificate verification - VERY insecure (optional)",
			},

			"starttls": {
				Type:        framework.TypeBool,
				Default:     true,
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
	}
}

const validCertificate = `
-----BEGIN CERTIFICATE-----
MIIENTCCAx2gAwIBAgIJAKczcv/REQveMA0GCSqGSIb3DQEBCwUAMIGwMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDU15c3RlcnkgQmVhY2gxHDAa
BgNVBAoME015c3RlcmllcyBVbmxpbWl0ZWQxFTATBgNVBAsMDFRoZSBTY29vYmll
czEZMBcGA1UEAwwQU2Nvb2J5IERvb2J5IERvbzEsMCoGCSqGSIb3DQEJARYdc2Nv
b2J5QG15c3Rlcmllc3VubGltaXRlZC5jb20wHhcNMTgwMzIwMjA1OTQ2WhcNMTkw
MzIwMjA1OTQ2WjCBsDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQH
DA1NeXN0ZXJ5IEJlYWNoMRwwGgYDVQQKDBNNeXN0ZXJpZXMgVW5saW1pdGVkMRUw
EwYDVQQLDAxUaGUgU2Nvb2JpZXMxGTAXBgNVBAMMEFNjb29ieSBEb29ieSBEb28x
LDAqBgkqhkiG9w0BCQEWHXNjb29ieUBteXN0ZXJpZXN1bmxpbWl0ZWQuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqtDPljP4Fns04ABD51LDuaja
tT6jMQakaO19+8f9j9s8pU42cbuipD/yaqSGlcYE/5cyAX8ri42tGeDZzrIA7pTJ
IiObWwifv/6h7m9vT4L/mIsGsJZ/5Et/uJG9q2k9iBf/Zh1zG2FSEVcNCMKbmjvl
xquiAaFhF6XKTK0IYbS213AuoVxmUZEmWZr5hslrekk7udqAhxn7YShrkt0lr6Cp
4xw+PGfR24N/jFBLMnmSmdAmWy566QlhfYNFFTH7TrLqf7qzJjNam11D+OAC4IpR
4GxX754hAJ5fRVz8WpT/53DH7p8PE9aUbM2agduBvQBQwygvOjT5weaYTgMFEwID
AQABo1AwTjAdBgNVHQ4EFgQUDykzcvmJn3gHx6QpYAGWLoxgXhYwHwYDVR0jBBgw
FoAUDykzcvmJn3gHx6QpYAGWLoxgXhYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAUq9mfNrc6iq6lCz4mYz/EFBFXMKYW8yqNXjJMolpDKWbFuGinWi9
wbYiq+GjjfX8ppftnEfCxhYNSFoAUMrqy7eCLrwDuG8kMPc5TCHMi8Lhw3WxOlfI
5mqInoHymANQZ8MPwNV13HjKnSpInE1DSb/Gi8YnWNwZNRkWlyKyiU6uMxi+zaM7
9JP9u1SYpbS55mRkbR+T89nZJjAEbQYGN5jJwMYcXlz83ncgzv7lUaugbcVfa8bG
zxHsjKTrh6lCFP7Q5aIqZ7ZI1hiXq8rKCtibsHJqSZw8woSviwfh5UDuiCmsoM1w
gx+My7Q9+fcEfWje/N8etdFpQp9WMDsPDg==
-----END CERTIFICATE-----
`
