package ldap

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap"
	"golang.org/x/text/encoding/unicode"
	"testing"
)

func TestCanChangeARealPassword(t *testing.T) {

	username := "redacted"
	password := "redacted"

	conf := &Configuration{
		Url: "ldap://138.91.247.105:389",
	}

	client := NewClient(conf)
	conn, err := client.DialLDAP()
	if err != nil {
		fmt.Println("couldn't dial ldap: " + err.Error())
		t.FailNow()
	}

	if err := conn.Bind(username, password); err != nil {
		fmt.Println("unable to bind: " + err.Error())
		t.FailNow()
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // TODO this is obviously not ideal..... :-)
	}
	if err := conn.StartTLS(tlsConf); err != nil {
		fmt.Println("couldn't start TLS: " + err.Error())
		t.FailNow()
	}

	// search for a user
	searchRequest := &ldap.SearchRequest{
		BaseDN: "dc=example,dc=com",
		Scope:  2,
		Filter: "(cn=Becca Petrin)",
	}
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		fmt.Println("search failed: " + err.Error())
		t.FailNow()
	}
	for _, entry := range searchResult.Entries {
		fmt.Printf("DN: %s\n", entry.DN)
		for _, attribute := range entry.Attributes {
			fmt.Printf("Name: %s; Values: %s\n", attribute.Name, attribute.Values)
		}
	}
	if len(searchResult.Entries) != 1 {
		fmt.Println("wuut? not just one entry?")
		t.FailNow()
	}
	fmt.Println("")

	// This is Active Directory specific because AD doesn't recognize the
	// passwordModify method.
	// See https://github.com/go-ldap/ldap/issues/106
	// This probably means this will need to be an Active Directory integration,
	// NOT an LDAP one. The integrations could be identical but there could
	// be a toggle on the client for which type it is, or something.
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	// According to the MS docs in the links above
	// The password needs to be enclosed in quotes
	pwdEncoded, err := utf16.NewEncoder().String("\"7KittyCatz?\"")
	if err != nil {
		fmt.Printf("unable to encode password: %s\n", err.Error())
		t.FailNow()
	}
	passReq := &ldap.ModifyRequest{
		DN: searchResult.Entries[0].DN,
		ReplaceAttributes: []ldap.PartialAttribute{
			{"unicodePwd", []string{pwdEncoded}},
		},
	}
	if err := conn.Modify(passReq); err != nil {
		fmt.Printf("unable to modify password: %s\n", err.Error())
		t.FailNow()
	}
	fmt.Println("successfully changed an active directory password!")
}
