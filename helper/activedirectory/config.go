package activedirectory

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/helper/tlsutil"
	"github.com/hashicorp/vault/logical/framework"
	"strings"
	"net/url"
	"crypto/tls"
	"net"
	"github.com/go-errors/errors"
	log "github.com/mgutz/logxi/v1"
)

const (
	DefaultTLSMinVersion = "tls12"
	DefaultTLSMaxVersion = "tls12"
)

func NewConfiguration(fieldData *framework.FieldData) (*Configuration, error) {

	conf := &Configuration{
		Username: fieldData.Get("username").(string),
		Password: fieldData.Get("password").(string),
		StartTLS: getStartTLS(fieldData),
	}

	tlsConfigs, err := getTLSConfigs(fieldData)
	if err != nil {
		return nil, err
	}
	conf.TlsConfigs = tlsConfigs

	if err := conf.validate(); err != nil {
		return nil, err
	}

	return conf, nil
}

type Configuration struct {
	Username      string `json:"username" structs:"username" mapstructure:"username"`
	Password      string `json:"password" structs:"password" mapstructure:"password"`
	StartTLS      bool   `json:"starttls" structs:"starttls" mapstructure:"starttls"`
	TlsConfigs    map[*url.URL]*tls.Config
}

func (c *Configuration) validate() error {

	if c.Username == "" {
		return errors.New("username must be provided")
	}

	if c.Password == "" {
		return errors.New("password must be provided")
	}

	if len(c.TlsConfigs) <= 0 {
		return errors.New("unable to parse any of the given urls")
	}

	return nil
}

func getStartTLS(fieldData *framework.FieldData) bool {

	startTLSIfc, ok := fieldData.GetOk("starttls")
	if !ok {
		return true
	}

	confStartTLS, ok := startTLSIfc.(bool)
	if !ok {
		return true
	}

	return confStartTLS
}

func getTLSConfigs(fieldData *framework.FieldData) (map[*url.URL]*tls.Config, error) {

	insecureTLS := fieldData.Get("insecure_tls").(bool)

	tlsMinVersion, err := getTLSMinVersion(fieldData)
	if err != nil {
		return nil, err
	}

	tlsMaxVersion, err := getTLSMaxVersion(fieldData)
	if err != nil {
		return nil, err
	}

	if tlsMinVersion < tlsMaxVersion {
		return nil, fmt.Errorf("'tls_max_version' must be greater than or equal to 'tls_min_version'")
	}

	certificate, err := getValidatedCertificate(fieldData)
	if err != nil {
		return nil, err
	}

	confUrls := strings.ToLower(fieldData.Get("url").(string))
	urls := strings.Split(confUrls, ",")

	tlsConfigs := make(map[*url.URL]*tls.Config)
	for _, uut := range urls {

		u, err := url.Parse(uut)
		if err != nil {
			log.Warn(fmt.Sprintf("unable to parse %s: %s, ignoring", uut, err.Error()))
			continue
		}

		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			// err intentionally ignored
			// fall back to using the parsed url's host
			host = u.Host
		}

		tlsConfig := &tls.Config{
			ServerName: host,
			MinVersion: tlsMinVersion,
			MaxVersion: tlsMaxVersion,
			InsecureSkipVerify: insecureTLS,
		}

		if certificate != "" {
			caPool := x509.NewCertPool()
			ok := caPool.AppendCertsFromPEM([]byte(certificate))
			if !ok {
				// this probably won't succeed on further attempts, so return
				return nil, fmt.Errorf("could not append CA certificate")
			}
			tlsConfig.RootCAs = caPool
		}

		tlsConfigs[u] = tlsConfig
	}

	return tlsConfigs, nil
}

func getTLSMinVersion(fieldData *framework.FieldData) (uint16, error) {

	confTLSMinVersion := fieldData.Get("tls_min_version").(string)
	if confTLSMinVersion == "" {
		confTLSMinVersion = DefaultTLSMinVersion
	}

	tlsMinVersion, ok := tlsutil.TLSLookup[confTLSMinVersion]
	if !ok {
		return 0, fmt.Errorf("invalid 'tls_min_version' in config")
	}

	return tlsMinVersion, nil
}

func getTLSMaxVersion(fieldData *framework.FieldData) (uint16, error) {

	confTLSMaxVersion := fieldData.Get("tls_max_version").(string)
	if confTLSMaxVersion == "" {
		confTLSMaxVersion = DefaultTLSMaxVersion
	}

	tlsMaxVersion, ok := tlsutil.TLSLookup[confTLSMaxVersion]
	if !ok {
		return 0, fmt.Errorf("invalid 'tls_max_version' in config")
	}

	return tlsMaxVersion, nil
}

func getValidatedCertificate(fieldData *framework.FieldData) (string, error) {

	confCertificate := fieldData.Get("certificate").(string)
	if confCertificate == "" {
		// no certificate was provided
		return "", nil
	}

	block, _ := pem.Decode([]byte(confCertificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("failed to decode PEM block in the certificate")
	}

	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate %s", err.Error())
	}

	return confCertificate, nil
}
