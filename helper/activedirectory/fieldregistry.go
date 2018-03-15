package activedirectory

import "fmt"

const (

	// Name fields
	CommonName     Field = "cn"
	DisplayName          = "displayName"
	GivenName            = "givenName"
	Name                 = "name"
	SAMAccountName       = "sAMAccountName"
	Surname              = "sn"

	// Misc. fields
	AccountExpires              = "accountExpires"
	BadPasswordCount            = "badPwdCount"
	BadPasswordTime             = "badPasswordTime"
	CodePage                    = "codePage"
	CountryCode                 = "countryCode"
	DistinguishedName           = "distinguishedName"
	DomainComponent             = "dc"
	DomainName                  = "dn"
	DSCorePropogationData       = "dSCorePropagationData"
	InstanceType                = "instanceType"
	LastLogoff                  = "lastLogoff"
	LastLogon                   = "lastLogon"
	LogonCount                  = "logonCount"
	MemberOf                    = "memberOf"
	ObjectCategory              = "objectCategory"
	ObjectClass                 = "objectClass"
	ObjectGUID                  = "objectGUID" // never changes
	ObjectSID                   = "objectSid"  // can sometimes change
	OrganizationalUnit          = "ou"
	PasswordLastSet             = "pwdLastSet"
	PrimaryGroupID              = "primaryGroupID"
	SAMAccountType              = "sAMAccountType"
	UnicodePassword             = "unicodePwd"
	UpdateSequenceNumberChanged = "uSNChanged"
	UpdateSequenceNumberCreated = "uSNCreated"
	UserAccountControl          = "userAccountControl"
	UserPrincipalName           = "userPrincipalName"
	WhenCreated                 = "whenCreated"
	WhenChanged                 = "whenChanged"
)

var fields = []Field{
	CommonName,
	DisplayName,
	GivenName,
	Name,
	SAMAccountName,
	Surname,
	AccountExpires,
	BadPasswordCount,
	BadPasswordTime,
	CodePage,
	CountryCode,
	DistinguishedName,
	DomainName,
	DSCorePropogationData,
	InstanceType,
	LastLogoff,
	LastLogon,
	LogonCount,
	MemberOf,
	ObjectCategory,
	ObjectClass,
	ObjectGUID,
	ObjectSID,
	PasswordLastSet,
	PrimaryGroupID,
	SAMAccountType,
	UpdateSequenceNumberChanged,
	UpdateSequenceNumberCreated,
	UserAccountControl,
	UserPrincipalName,
	WhenCreated,
	WhenChanged,
}

type Field string

func Parse(s string) (Field, error) {
	for _, f := range fields {
		if fmt.Sprintf("%s", f) == s {
			return f, nil
		}
	}
	return "", fmt.Errorf("no field matches %s", s)
}
