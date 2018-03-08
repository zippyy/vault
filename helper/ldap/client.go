package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-ldap/ldap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/helper/tlsutil"
	log "github.com/mgutz/logxi/v1"
	"net"
	"net/url"
	"strings"
)

func NewClient(conf *Configuration) Client {
	return &client{conf}
}

type Client interface {
	GetTLSConfig(host string) (*tls.Config, error)
	DialLDAP() (*ldap.Conn, error)
}

type client struct {
	conf *Configuration
}

func (c *client) GetTLSConfig(host string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		ServerName: host,
	}

	if c.conf.TLSMinVersion != "" {
		tlsMinVersion, ok := tlsutil.TLSLookup[c.conf.TLSMinVersion]
		if !ok {
			return nil, fmt.Errorf("invalid 'tls_min_version' in config")
		}
		tlsConfig.MinVersion = tlsMinVersion
	}

	if c.conf.TLSMaxVersion != "" {
		tlsMaxVersion, ok := tlsutil.TLSLookup[c.conf.TLSMaxVersion]
		if !ok {
			return nil, fmt.Errorf("invalid 'tls_max_version' in config")
		}
		tlsConfig.MaxVersion = tlsMaxVersion
	}

	if c.conf.InsecureTLS {
		tlsConfig.InsecureSkipVerify = true
	}
	if c.conf.Certificate != "" {
		caPool := x509.NewCertPool()
		ok := caPool.AppendCertsFromPEM([]byte(c.conf.Certificate))
		if !ok {
			return nil, fmt.Errorf("could not append CA certificate")
		}
		tlsConfig.RootCAs = caPool
	}
	return tlsConfig, nil
}

func (c *client) DialLDAP() (*ldap.Conn, error) {
	var retErr *multierror.Error
	var conn *ldap.Conn
	urls := strings.Split(c.conf.Url, ",")
	for _, uut := range urls {
		u, err := url.Parse(uut)
		if err != nil {
			retErr = multierror.Append(retErr, fmt.Errorf("error parsing url %q: %s", uut, err.Error()))
			continue
		}
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			host = u.Host
		}

		var tlsConfig *tls.Config
		switch u.Scheme {
		case "ldap":
			if port == "" {
				port = "389"
			}
			conn, err = ldap.Dial("tcp", net.JoinHostPort(host, port))
			if err != nil {
				break
			}
			if conn == nil {
				err = fmt.Errorf("empty connection after dialing")
				break
			}
			if c.conf.StartTLS {
				tlsConfig, err = c.GetTLSConfig(host)
				if err != nil {
					break
				}
				err = conn.StartTLS(tlsConfig)
			}
		case "ldaps":
			if port == "" {
				port = "636"
			}
			tlsConfig, err = c.GetTLSConfig(host)
			if err != nil {
				break
			}
			conn, err = ldap.DialTLS("tcp", net.JoinHostPort(host, port), tlsConfig)
		default:
			retErr = multierror.Append(retErr, fmt.Errorf("invalid LDAP scheme in url %q", net.JoinHostPort(host, port)))
			continue
		}
		if err == nil {
			if retErr != nil {
				if log.IsDebug() {
					log.Debug("ldap: errors connecting to some hosts: %s", retErr.Error())
				}
			}
			retErr = nil
			break
		}
		retErr = multierror.Append(retErr, fmt.Errorf("error connecting to host %q: %s", uut, err.Error()))
	}

	return conn, retErr.ErrorOrNil()
}
