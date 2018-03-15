package activedirectory

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/helper/tlsutil"
	"github.com/hashicorp/vault/logical/framework"
	"strings"
)

func NewConfiguration(fieldData *framework.FieldData) (*Configuration, error) {

	conf := &Configuration{}

	url := fieldData.Get("url").(string)
	if url != "" {
		conf.Url = strings.ToLower(url)
	}

	certificate := fieldData.Get("certificate").(string)
	if certificate != "" {
		block, _ := pem.Decode([]byte(certificate))

		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("failed to decode PEM block in the certificate")
		}
		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %s", err.Error())
		}
		conf.Certificate = certificate
	}

	insecureTLS := fieldData.Get("insecure_tls").(bool)
	if insecureTLS {
		conf.InsecureTLS = insecureTLS
	}

	conf.TLSMinVersion = fieldData.Get("tls_min_version").(string)
	if conf.TLSMinVersion == "" {
		return nil, fmt.Errorf("failed to get 'tls_min_version' value")
	}

	var ok bool
	_, ok = tlsutil.TLSLookup[conf.TLSMinVersion]
	if !ok {
		return nil, fmt.Errorf("invalid 'tls_min_version'")
	}

	conf.TLSMaxVersion = fieldData.Get("tls_max_version").(string)
	if conf.TLSMaxVersion == "" {
		return nil, fmt.Errorf("failed to get 'tls_max_version' value")
	}

	_, ok = tlsutil.TLSLookup[conf.TLSMaxVersion]
	if !ok {
		return nil, fmt.Errorf("invalid 'tls_max_version'")
	}
	if conf.TLSMaxVersion < conf.TLSMinVersion {
		return nil, fmt.Errorf("'tls_max_version' must be greater than or equal to 'tls_min_version'")
	}

	startTLS := fieldData.Get("starttls").(bool)
	if startTLS {
		conf.StartTLS = startTLS
	}

	return conf, nil
}

type Configuration struct {
	Url           string `json:"url" structs:"url" mapstructure:"url"`
	Certificate   string `json:"certificate" structs:"certificate" mapstructure:"certificate"`
	InsecureTLS   bool   `json:"insecure_tls" structs:"insecure_tls" mapstructure:"insecure_tls"`
	StartTLS      bool   `json:"starttls" structs:"starttls" mapstructure:"starttls"`
	TLSMinVersion string `json:"tls_min_version" structs:"tls_min_version" mapstructure:"tls_min_version"`
	TLSMaxVersion string `json:"tls_max_version" structs:"tls_max_version" mapstructure:"tls_max_version"`
	Username      string `json:"username" structs:"username" mapstructure:"username"`
	Password      string `json:"password" structs:"password" mapstructure:"password"`
}
