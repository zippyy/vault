package ldap

import (
	"testing"
	"fmt"
	"github.com/go-ldap/ldap"
)

func TestClientWorks(t *testing.T) {

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

	searchRequest := &ldap.SearchRequest{
		BaseDN: "dc=example,dc=com",
		Scope: 2,
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
}