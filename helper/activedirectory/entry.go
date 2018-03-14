package activedirectory

import (
	"github.com/go-ldap/ldap"
	"strings"
)

// Entry is an Active Directory-specific construct
// to make knowing and grabbing fields more convenient.
func NewEntry(ldapEntry *ldap.Entry) *Entry {
	m := make(map[Field][]string)
	for _, attribute := range ldapEntry.Attributes {
		field, err := Parse(attribute.Name)
		if err != nil {
			// TODO warn that an unexpected field was seen, but don't fail
			continue
		}
		m[field] = attribute.Values
	}
	return &Entry{m: m}
}

type Entry struct {
	m map[Field][]string
}

func (e *Entry) Get(field Field) ([]string, bool) {
	values, found := e.m[field]
	return values, found
}

func (e *Entry) GetJoined(field Field) (string, bool) {
	values, found := e.Get(field)
	if !found {
		return "", false
	}
	return strings.Join(values, ","), true
}
