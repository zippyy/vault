package activedirectory

import (
	"crypto/tls"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/go-ldap/ldap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/helper/ldapifc"
	log "github.com/mgutz/logxi/v1"
	"golang.org/x/text/encoding/unicode"
	"net"
	"net/url"
	"strings"
)

func NewClient(conf *Configuration) Client {
	return &client{conf, ldapifc.NewClient()}
}

// TODO this isn't in use yet but will be useful for injecting a mock for testing
func NewClientWith(conf *Configuration, ldapClient ldapifc.Client) Client {
	return &client{conf, ldapClient}
}

type Client interface {
	CreateEntry(baseDNValues []string, entry map[*Field][]string) error

	Search(baseDNValues []string, filters map[*Field][]string) ([]*Entry, error)

	UpdateEntry(baseDNValues []string, filters map[*Field][]string, newValues map[*Field][]string) error

	UpdatePassword(baseDNValues []string, filters map[*Field][]string, newPassword string) error
}

type client struct {
	conf       *Configuration
	ldapClient ldapifc.Client
}

func (c *client) CreateEntry(baseDNValues []string, entry map[*Field][]string) error {
	// TODO
	return nil
}

func (c *client) Search(baseDNValues []string, filters map[*Field][]string) ([]*Entry, error) {

	req := &ldap.SearchRequest{
		BaseDN: toDNString(baseDNValues),
		Scope:  ldap.ScopeWholeSubtree,
		Filter: toFilterString(filters),
	}

	conn, err := c.getFirstSucceedingConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	entries := make([]*Entry, len(result.Entries))
	for i, rawEntry := range result.Entries {
		entries[i] = NewEntry(rawEntry)
	}
	return entries, nil
}

func (c *client) UpdateEntry(baseDNValues []string, filters map[*Field][]string, newValues map[*Field][]string) error {

	entries, err := c.Search(baseDNValues, filters)
	if err != nil {
		return err
	}
	if len(entries) != 1 {
		return fmt.Errorf("filter of %s doesn't match just one entry: %s", filters, entries)
	}

	replaceAttributes := make([]ldap.PartialAttribute, len(newValues))
	i := 0
	for field, vals := range newValues {
		replaceAttributes[i] = ldap.PartialAttribute{
			Type: field.String(),
			Vals: vals,
		}
		i++
	}

	modifyReq := &ldap.ModifyRequest{
		DN:                entries[0].DN,
		ReplaceAttributes: replaceAttributes,
	}

	conn, err := c.getFirstSucceedingConnection()
	if err != nil {
		return err
	}

	return conn.Modify(modifyReq)
}

func (c *client) UpdatePassword(baseDNValues []string, filters map[*Field][]string, newPassword string) error {

	if !c.conf.StartTLS {
		return errors.New("per Active Directory, a TLS session must be in progress to update passwords, please update your StartTLS setting")
	}

	// Active Directory doesn't recognize the passwordModify method.
	// See https://github.com/go-ldap/ldap/issues/106
	// for further description, and for this workaround.
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)

	// According to the MS docs, the password needs to be enclosed in quotes.
	pwdEncoded, err := utf16.NewEncoder().String("\"" + newPassword + "\"")
	if err != nil {
		return err
	}

	newValues := map[*Field][]string{
		FieldRegistry.UnicodePassword: {pwdEncoded},
	}

	return c.UpdateEntry(baseDNValues, filters, newValues)
}

func (c *client) getFirstSucceedingConnection() (*ldap.Conn, error) {

	var retErr *multierror.Error

	tlsConfigs, err := c.conf.GetTLSConfigs()
	if err != nil {
		return nil, err
	}

	for u, tlsConfig := range tlsConfigs {
		conn, err := c.connect(u, tlsConfig)
		if err != nil {
			retErr = multierror.Append(retErr, fmt.Errorf("error parsing url %v: %v", u, err.Error()))
			continue
		}

		if c.conf.Username != "" && c.conf.Password != "" {
			if err := conn.Bind(c.conf.Username, c.conf.Password); err != nil {
				retErr = multierror.Append(retErr, fmt.Errorf("error binding to url %s: %s", u, err.Error()))
				continue
			}
		}

		return conn, nil
	}

	// TODO do I need to check if log IsDebug first, or will the logger handle only printing it if the level is appropriate?
	log.Debug("ldap: errors connecting to some hosts: %s", retErr.Error())
	return nil, retErr
}

func (c *client) connect(u *url.URL, tlsConfig *tls.Config) (*ldap.Conn, error) {

	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// err intentionally ignored - we'll fall back to default ldap ports if we're unable to parse this
	}

	switch u.Scheme {

	case "ldap":

		if port == "" {
			port = "389"
		}

		conn, err := ldap.Dial("tcp", net.JoinHostPort(tlsConfig.ServerName, port))
		if err != nil {
			return nil, err
		}

		if c.conf.StartTLS {
			if err = conn.StartTLS(tlsConfig); err != nil {
				return nil, err
			}
		}
		return conn, nil

	case "ldaps":

		if port == "" {
			port = "636"
		}

		conn, err := ldap.DialTLS("tcp", net.JoinHostPort(tlsConfig.ServerName, port), tlsConfig)
		if err != nil {
			return nil, err
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("invalid LDAP scheme in url %q", net.JoinHostPort(tlsConfig.ServerName, port))
	}
}

func toDNString(dnValues []string) string {
	m := map[*Field][]string{
		FieldRegistry.DomainComponent: dnValues,
	}
	return toJoinedFieldEqualsString(m)
}

// Ex. "dc=example,dc=com"
func toJoinedFieldEqualsString(fieldValues map[*Field][]string) string {
	var fieldEquals []string
	for f, values := range fieldValues {
		for _, v := range values {
			fieldEquals = append(fieldEquals, fmt.Sprintf("%s=%s", f, v))
		}
	}
	return strings.Join(fieldEquals, ",")
}

// Ex. "(cn=Ellen Jones)"
func toFilterString(filters map[*Field][]string) string {
	result := toJoinedFieldEqualsString(filters)
	return "(" + result + ")"
}
