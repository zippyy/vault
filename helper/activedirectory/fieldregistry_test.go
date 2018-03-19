package activedirectory

import (
	"testing"
	"github.com/magiconair/properties/assert"
)

func TestFieldRegistryListsFields(t *testing.T) {
	fields := FieldRegistry.List()
	assert.Equal(t, 36, len(fields))
}

func TestFieldRegistryEqualityComparisonsWork(t *testing.T) {

	fields := FieldRegistry.List()

	foundGivenName := false
	foundSurname := false

	for _, field := range fields {
		if field == FieldRegistry.GivenName {
			foundGivenName = true
		}
		if field == FieldRegistry.Surname {
			foundSurname = true
		}
	}

	assert.Equal(t, foundGivenName, true)
	assert.Equal(t, foundSurname, true)
}

func TestFieldRegistryParsesFieldsByString(t *testing.T) {

	field, err := FieldRegistry.Parse("sn")
	if err != nil {
		t.Errorf("couldn't parse field: %s", err)
		t.FailNow()
	}

	assert.Equal(t, FieldRegistry.Surname, field)
}