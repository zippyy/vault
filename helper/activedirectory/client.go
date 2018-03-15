package activedirectory

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-ldap/ldap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/helper/tlsutil"
	log "github.com/mgutz/logxi/v1"
	"golang.org/x/text/encoding/unicode"
	"net"
	"net/url"
	"strings"
	"github.com/hashicorp/vault/helper/ldapifc"
	"github.com/go-errors/errors"
)

func NewClient(conf *Configuration) Client {
	return &client{conf, ldapifc.NewClient()}
}

// TODO this is kind of a stupid name
func NewClientWith(conf *Configuration, ldapClient ldapifc.Client) Client {
	return &client{conf, ldapClient}
}

type Client interface {
	Search(baseDN map[Field][]string, filters map[Field][]string) ([]*Entry, error)
	UpdateEntry(baseDN map[Field][]string, filters map[Field][]string, newValues map[Field][]string) error // TODO add test

	// UpdatePassword sets a new password for one user.
	UpdatePassword(baseDN map[Field][]string, filters map[Field][]string, newPassword string) error

	// UpdateUsername is a convenience method for updating usernames.
	// It updates the following fields:
	//     - CommonName
	//     - DisplayName
	//     - GivenName
	//     - Name
	//     - Surname
	// It does not update these fields so emails and SAM automation will be unaffected.
	//     - userPrincipalName
	//     - SAMAccountName
	// If a different set of fields is desired, use UpdateEntry and specify the fields directly instead.
	// TODO it turns out the userPrincipal name uses everything before @ for the login name, ex. becca@example.com so I log in as becca
	UpdateUsername(baseDN map[Field][]string, filters map[Field][]string, newUsername *Username) error
}

type client struct {
	conf *Configuration
	ldapClient ldapifc.Client
}

func (c *client) Search(baseDN map[Field][]string, filters map[Field][]string) ([]*Entry, error) {

	req := &ldap.SearchRequest{
		BaseDN: toDNString(baseDN),
		Scope:  2, // TODO ???
		Filter: toFilterString(filters),
	}

	conn, err := c.getBoundConnection()
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

func (c *client) UpdateEntry(baseDN map[Field][]string, filters map[Field][]string, newValues map[Field][]string) error {

	entries, err := c.Search(baseDN, filters)
	if err != nil {
		return err
	}
	if len(entries) != 1 {
		return fmt.Errorf("filter of %s doesn't match just one entry: %s", filters, entries)
	}

	replaceAttributes := make([]ldap.PartialAttribute, len(newValues))
	i := 0
	for k, v := range newValues {
		replaceAttributes[i] = ldap.PartialAttribute{
			Type: fmt.Sprintf("%s", k),
			Vals: v,
		}
		i++
	}

	modifyReq := &ldap.ModifyRequest{
		DN: entries[0].DN,
		ReplaceAttributes: replaceAttributes,
	}

	conn, err := c.getBoundConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Modify(modifyReq)
}

func (c *client) UpdatePassword(baseDN map[Field][]string, filters map[Field][]string, newPassword string) error {

	if !c.conf.StartTLS {
		return errors.New("per Active Directory, a TLS session must be in progress to update passswords, please update your StartTLS setting")
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

	newValues := map[Field][]string {
		UnicodePassword: {pwdEncoded},
	}

	return c.UpdateEntry(baseDN, filters, newValues)
}

type Username struct {
	FirstName string // ex. "Becca"
	Initials string // ex. "A"
	LastName string // ex. "Petrin"
}

func (c *client) UpdateUsername(baseDN map[Field][]string, filters map[Field][]string, newUsername *Username) error {

	// Validate that we received an expected username so we can do gymnastics to format various fields.
	if !isMixedCase(newUsername.FirstName) {
		return fmt.Errorf("expected first name %s to be mixed case, ex. 'Tien'", newUsername.FirstName)
	}
	if !isValidInitial(newUsername.Initials) {
		return fmt.Errorf("expected initial %s to be capitalized and without a period, ex. 'W'", newUsername.Initials)
	}
	if !isMixedCase(newUsername.LastName) {
		return fmt.Errorf("expected last name %s to be mixed case, ex. 'Nguyen'", newUsername.LastName)
	}

	newFullName := fmt.Sprintf("%s %s. %s", newUsername.FirstName, newUsername.Initials, newUsername.LastName)

	newValues := map[Field][]string {
		//CommonName: {newFullName},
		DisplayName: {newFullName},
		GivenName: {newUsername.FirstName},
		//Name: {newFullName},
		Surname: {newUsername.LastName},
	}

	return c.UpdateEntry(baseDN, filters, newValues)
}

func (c *client) getBoundConnection() (*ldap.Conn, error) {

	var retErr *multierror.Error

	urls := strings.Split(c.conf.Url, ",")
	for _, uut := range urls {
		conn, err := c.connect(uut)
		if err != nil {
			retErr = multierror.Append(retErr, fmt.Errorf("error parsing url %q: %s", uut, err.Error()))
			continue
		}
		if err := conn.Bind(c.conf.Username, c.conf.Password); err != nil {
			retErr = multierror.Append(retErr, fmt.Errorf("error binding to url %q: %s", uut, err.Error()))
			continue
		}
		return conn, nil
	}

	log.Debug("ldap: errors connecting to some hosts: %s", retErr.Error())
	return nil, retErr
}

func (c *client) connect(uut string) (*ldap.Conn, error) {

	// TODO these probably should just be parsed once, not on every connection
	u, err := url.Parse(uut)
	if err != nil {
		return nil, err
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// err intentionally ignored
		// fall back to using the parsed url's host
		host = u.Host
	}

	var tlsConfig *tls.Config

	switch u.Scheme {

	case "ldap":

		if port == "" {
			port = "389"
		}

		conn, err := ldap.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			return nil, err
		}

		if c.conf.StartTLS {

			tlsConfig, err = c.getTLSConfig(host)
			if err != nil {
				return nil, err
			}
			if err = conn.StartTLS(tlsConfig); err != nil {
				return nil, err
			}
		}
		return conn, nil

	case "ldaps":

		if port == "" {
			port = "636"
		}

		tlsConfig, err = c.getTLSConfig(host)
		if err != nil {
			return nil, err
		}

		conn, err := ldap.DialTLS("tcp", net.JoinHostPort(host, port), tlsConfig)
		if err != nil {
			return nil, err
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("invalid LDAP scheme in url %q", net.JoinHostPort(host, port))
	}
}

func (c *client) getTLSConfig(host string) (*tls.Config, error) {

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

// Ex. "dc=example,dc=com"
func toDNString(baseDN map[Field][]string) string {
	var fieldValues []string
	for f, values := range baseDN {
		for _, v := range values {
			fieldValues = append(fieldValues, fmt.Sprintf("%s=%s", f, v))
		}
	}
	return strings.Join(fieldValues, ",")
}

// Ex. "(cn=Ellen Jones)"
func toFilterString(filters map[Field][]string) string {
	result := toDNString(filters)
	return "(" + result + ")"
}

func isValidInitial(s string) bool {
	if strings.ToUpper(s) != s {
		return false
	}
	if strings.HasSuffix(s, ".") {
		return false
	}
	return true
}

func isMixedCase(s string) bool {
	if strings.ToUpper(s) == s {
		return false
	}
	if strings.ToLower(s) == s {
		return false
	}
	return true
}
