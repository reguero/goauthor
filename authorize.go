package main

import (
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/go-ldap/ldap"
)

func main() {
	fmt.Printf("This is an authorization proof of concept\n")
	if checkEgroup("ermis-lbaas-admins", "reguero") == true {
		fmt.Printf("true\n")
	} else {
		fmt.Printf("false\n")
	}
	if checkEgroup("spanish-gang", "marquina") == true {
		fmt.Printf("true\n")
	} else {
		fmt.Printf("false\n")
	}
	if checkEgroup("ermis-lbaas-admins", "toto") == true {
		fmt.Printf("true\n")
	} else {
		fmt.Printf("false\n")
	}
	if checkEgroup("ermis-lbaas-admins", "marquina") == true {
		fmt.Printf("true\n")
	} else {
		fmt.Printf("false\n")
	}
	if checkEgroup("toto", "reguero") == true {
		fmt.Printf("true\n")
	} else {
		fmt.Printf("false\n")
	}
	if checkEgroup("ai-training", "reguero") == true {
		fmt.Printf("true\n")
	} else {
		fmt.Printf("false\n")
	}
	os.Exit(0)

}

func checkEgroup(egroup string, username string) bool {
	l, err := ldap.Dial("tcp", "xldap.cern.ch:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	found := false
	baseSuffix := "OU=Users,OU=Organic Units,DC=cern,DC=ch"
	base := fmt.Sprintf("CN=%s,%s", username, baseSuffix)
	filterSuffix := "OU=e-groups,OU=Workgroups,DC=cern,DC=ch)"
	filter := fmt.Sprintf("(memberOf=CN=%s,%s", egroup, filterSuffix)
	nestedFilter := fmt.Sprintf("(memberOf:1.2.840.113556.1.4.1941:=CN=%s,%s", egroup, filterSuffix)
	exclDisabledPrefix := "(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|"
	attrs := []string{"cn"}
	exclDisabled := true
	if exclDisabled {
		filter = exclDisabledPrefix + filter + "))"
		nestedFilter = exclDisabledPrefix + nestedFilter + "))"
	}
	searchRequest := ldap.NewSearchRequest(
		base, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, // The filter to apply
		attrs,  // A list attributes to retrieve
		nil,
	)

	re := regexp.MustCompile(".*No Such Object")
	sr, err := l.Search(searchRequest)
	if err != nil {
		found = false
		submatch := re.FindStringSubmatch(err.Error())
		if submatch != nil {
			fmt.Printf("Username not found\n")
		} else {
			log.Fatal(err)
		}
	} else {
		found = true
		if len(sr.Entries) == 0 {
			fmt.Printf("Retrying\n")
			nestedSearchRequest := ldap.NewSearchRequest(
				base, // The base dn to search
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				nestedFilter, // The filter to apply
				attrs,        // A list attributes to retrieve
				nil,
			)
			sr, err = l.Search(nestedSearchRequest)
			if err != nil {
				log.Fatal(err)
				found = false
			} else {
				if len(sr.Entries) == 0 {
					found = false
				}
			}
		}
	}
	if found == true {
		for _, entry := range sr.Entries {
			fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
		}
	}
	return found
}
