package activedirectory

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/go-ldap/ldap"
	"github.com/hashicorp/vault/helper/ldapifc"
	"github.com/magiconair/properties/assert"
)

var (
	username = os.Getenv("TEST_LDAP_USERNAME")
	password = os.Getenv("TEST_LDAP_PASSWORD")
	rawURL   = os.Getenv("TEST_LDAP_URL")
)

func TestCreateEntry(t *testing.T) {
	// TODO
}

func TestSearch(t *testing.T) {

	config, err := getConfig(username, password, rawURL)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	client := NewClient(config)

	baseDN := []string{"example", "com"}

	filters := map[*Field][]string{
		FieldRegistry.Surname: {"Kalafut"},
	}

	entries, err := client.Search(baseDN, filters)

	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if len(entries) != 1 {
		t.Errorf("expected 1 entry but received %d: %s", len(entries), entries)
		t.FailNow()
	}
	entry := entries[0]

	result, _ := entry.GetJoined(FieldRegistry.SAMAccountName)
	assert.Equal(t, result, "jim")

	result, _ = entry.GetJoined(FieldRegistry.CommonName)
	assert.Equal(t, result, "Jim H.. Kalafut")

	result, _ = entry.GetJoined(FieldRegistry.GivenName)
	assert.Equal(t, result, "Jim")

	result, _ = entry.GetJoined(FieldRegistry.DisplayName)
	assert.Equal(t, result, "Jim H.. Kalafut")

	result, _ = entry.GetJoined(FieldRegistry.BadPasswordTime)
	assert.Equal(t, result, "131653637947737037")

	result, _ = entry.GetJoined(FieldRegistry.PasswordLastSet)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(FieldRegistry.PrimaryGroupID)
	assert.Equal(t, result, "513")

	result, _ = entry.GetJoined(FieldRegistry.AccountExpires)
	assert.Equal(t, result, "9223372036854775807")

	result, _ = entry.GetJoined(FieldRegistry.WhenCreated)
	assert.Equal(t, result, "20180312181537.0Z")

	result, _ = entry.GetJoined(FieldRegistry.UpdateSequenceNumberCreated)
	assert.Equal(t, result, "20565")

	result, _ = entry.GetJoined(FieldRegistry.UpdateSequenceNumberChanged)
	assert.Equal(t, result, "20571")

	result, _ = entry.GetJoined(FieldRegistry.BadPasswordCount)
	assert.Equal(t, result, "1")

	result, _ = entry.GetJoined(FieldRegistry.UserPrincipalName)
	assert.Equal(t, result, "jim@example.com")

	result, _ = entry.GetJoined(FieldRegistry.ObjectCategory)
	assert.Equal(t, result, "CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com")

	result, _ = entry.GetJoined(FieldRegistry.DSCorePropogationData)
	assert.Equal(t, result, "16010101000000.0Z")

	result, _ = entry.GetJoined(FieldRegistry.LastLogoff)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(FieldRegistry.LastLogon)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(FieldRegistry.SAMAccountType)
	assert.Equal(t, result, "805306368")

	result, _ = entry.GetJoined(FieldRegistry.CountryCode)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(FieldRegistry.Surname)
	assert.Equal(t, result, "Kalafut")

	result, _ = entry.GetJoined(FieldRegistry.DistinguishedName)
	assert.Equal(t, result, "CN=Jim H.. Kalafut,OU=Vault,OU=Engineering,DC=example,DC=com")

	result, _ = entry.GetJoined(FieldRegistry.ObjectClass)
	assert.Equal(t, result, "top,person,organizationalPerson,user")

	result, _ = entry.GetJoined(FieldRegistry.InstanceType)
	assert.Equal(t, result, "4")

	result, _ = entry.GetJoined(FieldRegistry.WhenChanged)
	assert.Equal(t, result, "20180312181537.0Z")

	result, _ = entry.GetJoined(FieldRegistry.CodePage)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(FieldRegistry.LogonCount)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(FieldRegistry.Name)
	assert.Equal(t, result, "Jim H.. Kalafut")

	result, _ = entry.GetJoined(FieldRegistry.UserAccountControl)
	assert.Equal(t, result, "512")
}

func TestUpdateEntry(t *testing.T) {
	// TODO
}

func TestUpdatePassword(t *testing.T) {
	// TODO
}

// TODO the below isn't in use yet but will be used as a mock in final tests
type fakeLDAPClient struct {
	connToReturn ldapifc.Connection
}

func (f *fakeLDAPClient) Dial(network, addr string) (ldapifc.Connection, error) {
	return f.connToReturn, nil
}

func (f *fakeLDAPClient) DialTLS(network, addr string, config *tls.Config) (ldapifc.Connection, error) {
	return f.connToReturn, nil
}

type fakeLDAPConnection struct {
	usernameToExpect string
	passwordToExpect string

	modifyRequestToExpect *ldap.ModifyRequest

	searchRequestToExpect *ldap.SearchRequest
	searchResultToReturn  *ldap.SearchResult

	startTLSConfigToExpect *tls.Config
}

func (f *fakeLDAPConnection) Bind(username, password string) error {
	if f.usernameToExpect != username {
		return fmt.Errorf("expected username of %s, but received %s", f.usernameToExpect, username)
	}
	if f.passwordToExpect != password {
		return fmt.Errorf("expected password of %s, but received %s", f.passwordToExpect, password)
	}
	return nil
}

func (f *fakeLDAPConnection) Close() {}

func (f *fakeLDAPConnection) Modify(modifyRequest *ldap.ModifyRequest) error {
	if f.modifyRequestToExpect != modifyRequest {
		return fmt.Errorf("expected modifyRequest of %s, but received %s", f.modifyRequestToExpect, modifyRequest)
	}
	return nil
}

func (f *fakeLDAPConnection) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.searchRequestToExpect != searchRequest {
		return nil, fmt.Errorf("expected searchRequest of %v, but received %v", f.searchRequestToExpect, searchRequest)
	}
	return f.searchResultToReturn, nil
}

func (f *fakeLDAPConnection) StartTLS(config *tls.Config) error {
	if f.startTLSConfigToExpect != config {
		return fmt.Errorf("expected tlsConfig of %v, but received %v", f.startTLSConfigToExpect, config)
	}
	return nil
}

func getConfig(username string, password string, rawURL string) (*Configuration, error) {

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	var tlsMinVersion uint16
	var tlsMaxVersion uint16

	tlsMinVersion = 771
	tlsMaxVersion = 771

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		// err intentionally ignored
		// fall back to using the parsed url's host
		host = u.Host
	}

	tlsConfig := &tls.Config{
		ServerName:         host,
		MinVersion:         tlsMinVersion,
		MaxVersion:         tlsMaxVersion,
		InsecureSkipVerify: true,
	}

	return &Configuration{
		StartTLS: false,
		Username: username,
		Password: password,
		tlsConfigs: map[*url.URL]*tls.Config{
			u: tlsConfig,
		},
	}, nil
}
