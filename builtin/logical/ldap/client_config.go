package ldap

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/helper/tlsutil"
	"github.com/hashicorp/vault/logical/framework"
	"strings"
	"text/template"
)

func newClientConfig(d *framework.FieldData) (*clientConfig, error) {

	cfg := &clientConfig{}

	url := d.Get("url").(string)
	if url != "" {
		cfg.Url = strings.ToLower(url)
	}
	userattr := d.Get("userattr").(string)
	if userattr != "" {
		cfg.UserAttr = strings.ToLower(userattr)
	}
	userdn := d.Get("userdn").(string)
	if userdn != "" {
		cfg.UserDN = userdn
	}
	groupdn := d.Get("groupdn").(string)
	if groupdn != "" {
		cfg.GroupDN = groupdn
	}
	groupfilter := d.Get("groupfilter").(string)
	if groupfilter != "" {
		// Validate the template before proceeding
		_, err := template.New("queryTemplate").Parse(groupfilter)
		if err != nil {
			return nil, fmt.Errorf("invalid groupfilter (%v)", err)
		}

		cfg.GroupFilter = groupfilter
	}
	groupattr := d.Get("groupattr").(string)
	if groupattr != "" {
		cfg.GroupAttr = groupattr
	}
	upndomain := d.Get("upndomain").(string)
	if upndomain != "" {
		cfg.UPNDomain = upndomain
	}
	certificate := d.Get("certificate").(string)
	if certificate != "" {
		block, _ := pem.Decode([]byte(certificate))

		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("failed to decode PEM block in the certificate")
		}
		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %s", err.Error())
		}
		cfg.Certificate = certificate
	}
	insecureTLS := d.Get("insecure_tls").(bool)
	if insecureTLS {
		cfg.InsecureTLS = insecureTLS
	}
	cfg.TLSMinVersion = d.Get("tls_min_version").(string)
	if cfg.TLSMinVersion == "" {
		return nil, fmt.Errorf("failed to get 'tls_min_version' value")
	}

	var ok bool
	_, ok = tlsutil.TLSLookup[cfg.TLSMinVersion]
	if !ok {
		return nil, fmt.Errorf("invalid 'tls_min_version'")
	}

	cfg.TLSMaxVersion = d.Get("tls_max_version").(string)
	if cfg.TLSMaxVersion == "" {
		return nil, fmt.Errorf("failed to get 'tls_max_version' value")
	}

	_, ok = tlsutil.TLSLookup[cfg.TLSMaxVersion]
	if !ok {
		return nil, fmt.Errorf("invalid 'tls_max_version'")
	}
	if cfg.TLSMaxVersion < cfg.TLSMinVersion {
		return nil, fmt.Errorf("'tls_max_version' must be greater than or equal to 'tls_min_version'")
	}

	startTLS := d.Get("starttls").(bool)
	if startTLS {
		cfg.StartTLS = startTLS
	}
	bindDN := d.Get("binddn").(string)
	if bindDN != "" {
		cfg.BindDN = bindDN
	}
	bindPass := d.Get("bindpass").(string)
	if bindPass != "" {
		cfg.BindPassword = bindPass
	}
	denyNullBind := d.Get("deny_null_bind").(bool)
	if denyNullBind {
		cfg.DenyNullBind = denyNullBind
	}
	discoverDN := d.Get("discoverdn").(bool)
	if discoverDN {
		cfg.DiscoverDN = discoverDN
	}
	return cfg, nil
}

type clientConfig struct {
	Url           string `json:"url" structs:"url" mapstructure:"url"`
	UserDN        string `json:"userdn" structs:"userdn" mapstructure:"userdn"`
	GroupDN       string `json:"groupdn" structs:"groupdn" mapstructure:"groupdn"`
	GroupFilter   string `json:"groupfilter" structs:"groupfilter" mapstructure:"groupfilter"`
	GroupAttr     string `json:"groupattr" structs:"groupattr" mapstructure:"groupattr"`
	UPNDomain     string `json:"upndomain" structs:"upndomain" mapstructure:"upndomain"`
	UserAttr      string `json:"userattr" structs:"userattr" mapstructure:"userattr"`
	Certificate   string `json:"certificate" structs:"certificate" mapstructure:"certificate"`
	InsecureTLS   bool   `json:"insecure_tls" structs:"insecure_tls" mapstructure:"insecure_tls"`
	StartTLS      bool   `json:"starttls" structs:"starttls" mapstructure:"starttls"`
	BindDN        string `json:"binddn" structs:"binddn" mapstructure:"binddn"`
	BindPassword  string `json:"bindpass" structs:"bindpass" mapstructure:"bindpass"`
	DenyNullBind  bool   `json:"deny_null_bind" structs:"deny_null_bind" mapstructure:"deny_null_bind"`
	DiscoverDN    bool   `json:"discoverdn" structs:"discoverdn" mapstructure:"discoverdn"`
	TLSMinVersion string `json:"tls_min_version" structs:"tls_min_version" mapstructure:"tls_min_version"`
	TLSMaxVersion string `json:"tls_max_version" structs:"tls_max_version" mapstructure:"tls_max_version"`
}
