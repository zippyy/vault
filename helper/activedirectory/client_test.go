package activedirectory

import (
	"testing"
	"github.com/magiconair/properties/assert"
	"github.com/hashicorp/vault/helper/ldapifc"
	"crypto/tls"
	"github.com/go-ldap/ldap"
	"fmt"
)

var completeConfig = &Configuration{
	StartTLS:      false,
	Username:      "redacted",
	Password:      "redacted",
}

func TestSearch(t *testing.T) {

	client := NewClient(completeConfig)

	baseDN := map[Field][]string{
		DomainComponent: {"example", "com"},
	}

	filters := map[Field][]string{
		Surname: {"Kalafut"},
	}

	entries, err := client.Search(baseDN, filters)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry but received %d: %s", len(entries), entries)
		t.FailNow()
	}
	entry := entries[0]

	result, _ := entry.GetJoined(SAMAccountName)
	assert.Equal(t, result, "jim")

	result, _ = entry.GetJoined(CommonName)
	assert.Equal(t, result, "Jim H.. Kalafut")

	result, _ = entry.GetJoined(GivenName)
	assert.Equal(t, result, "Jim")

	result, _ = entry.GetJoined(DisplayName)
	assert.Equal(t, result, "Jim H.. Kalafut")

	result, _ = entry.GetJoined(BadPasswordTime)
	assert.Equal(t, result, "131653637947737037")

	result, _ = entry.GetJoined(PasswordLastSet)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(PrimaryGroupID)
	assert.Equal(t, result, "513")

	result, _ = entry.GetJoined(AccountExpires)
	assert.Equal(t, result, "9223372036854775807")

	result, _ = entry.GetJoined(WhenCreated)
	assert.Equal(t, result, "20180312181537.0Z")

	result, _ = entry.GetJoined(UpdateSequenceNumberCreated)
	assert.Equal(t, result, "20565")

	result, _ = entry.GetJoined(UpdateSequenceNumberChanged)
	assert.Equal(t, result, "20571")

	result, _ = entry.GetJoined(BadPasswordCount)
	assert.Equal(t, result, "1")

	result, _ = entry.GetJoined(UserPrincipalName)
	assert.Equal(t, result, "jim@example.com")

	result, _ = entry.GetJoined(ObjectCategory)
	assert.Equal(t, result, "CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com")

	result, _ = entry.GetJoined(DSCorePropogationData)
	assert.Equal(t, result, "16010101000000.0Z")

	result, _ = entry.GetJoined(LastLogoff)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(LastLogon)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(SAMAccountType)
	assert.Equal(t, result, "805306368")

	result, _ = entry.GetJoined(CountryCode)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(Surname)
	assert.Equal(t, result, "Kalafut")

	result, _ = entry.GetJoined(DistinguishedName)
	assert.Equal(t, result, "CN=Jim H.. Kalafut,OU=Vault,OU=Engineering,DC=example,DC=com")

	result, _ = entry.GetJoined(ObjectClass)
	assert.Equal(t, result, "top,person,organizationalPerson,user")

	result, _ = entry.GetJoined(InstanceType)
	assert.Equal(t, result, "4")

	result, _ = entry.GetJoined(WhenChanged)
	assert.Equal(t, result, "20180312181537.0Z")

	result, _ = entry.GetJoined(CodePage)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(LogonCount)
	assert.Equal(t, result, "0")

	result, _ = entry.GetJoined(Name)
	assert.Equal(t, result, "Jim H.. Kalafut")

	result, _ = entry.GetJoined(UserAccountControl)
	assert.Equal(t, result, "512")
}

func TestUpdatePassword(t *testing.T) {

	customConfig := completeConfig
	customConfig.StartTLS = true

	client := NewClient(customConfig)

	baseDN := map[Field][]string{
		DomainComponent: {"example", "com"},
	}

	filters := map[Field][]string{
		Surname: {"Test"},
	}

	if err := client.UpdatePassword(baseDN, filters, "7Zoinks?"); err != nil {
		t.Errorf("error updating password: %s", err.Error())
		t.FailNow()
	}
}

func TestUpdatePasswordFailsHelpfullyWithNoTLSSession(t *testing.T) {

	client := NewClient(completeConfig)

	baseDN := map[Field][]string{
		DomainComponent: {"example", "com"},
	}

	filters := map[Field][]string{
		Surname: {"Test"},
	}

	if err := client.UpdatePassword(baseDN, filters, "redacted"); err != nil {
		assert.Equal(t, err.Error(), "per Active Directory, a TLS session must be in progress to update passswords, please update your StartTLS setting")
		return
	}
	t.Error("should have errored because MS won't update passwords without a TLS session")
	t.FailNow()
}

// TODO MS is odd about which fields on a name you can directly update,
// and so far I haven't found it documented.
// Need more definition on what they mean by updating the "username"
// before I can properly define the behavior of this method.
func TestUpdateUsername(t *testing.T) {

	client := NewClient(completeConfig)

	baseDN := map[Field][]string{
		DomainComponent: {"example", "com"},
	}

	filters := map[Field][]string{
		Surname: {"Test"},
	}

	newName := &Username{
		FirstName: "Pwd",
		Initials: "G",
		LastName: "Tester",
	}

	if err := client.UpdateUsername(baseDN, filters, newName); err != nil {
		t.Errorf("failed to update username: %s", err.Error())
		t.FailNow()
	}
}

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
	searchResultToReturn *ldap.SearchResult

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
		return nil, fmt.Errorf("expected searchRequest of %s, but received %s", f.searchRequestToExpect, searchRequest)
	}
	return f.searchResultToReturn, nil
}

func (f *fakeLDAPConnection) StartTLS(config *tls.Config) error {
	if f.startTLSConfigToExpect != config {
		return fmt.Errorf("expected tlsConfig of %s, but received %s", f.startTLSConfigToExpect, config)
	}
	return nil
}

