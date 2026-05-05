package ldap

import (
	"fmt"
)

// Binary ObjectSID Format:
// 		byte[0]   - Revision Level
//		byte[1]   - count of Sub-Authorities
//		byte[2-7] - 48 bit Authority (big-endian)
//		byte[8+]  - n Sub-Authorities, 32 bits each (little-endian)
// String ObjectSID Format:
// 		S-{Revision}-{Authority}-{SubAuthority1}-{SubAuthority2}...-{SubAuthorityN}
//
// get more information about SID format:
// https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

type ObjectSID struct {
	RevisionLevel     int
	SubAuthorityCount int
	Authority         int
	SubAuthorities    []int
	RelativeID        *int
}

func (sid ObjectSID) String() string {
	s := fmt.Sprintf("S-%d-%d", sid.RevisionLevel, sid.Authority)
	for _, v := range sid.SubAuthorities {
		s += fmt.Sprintf("-%d", v)
	}
	return s
}

func SIDDecode(b []byte) ObjectSID {
	var sid ObjectSID

	sid.RevisionLevel = int(b[0])
	sid.SubAuthorityCount = int(b[1]) & 0xFF

	for i := 2; i <= 7; i++ {
		sid.Authority = sid.Authority | int(b[i])<<(8*(5-(i-2)))
	}

	var offset = 8
	var size = 4
	for i := 0; i < sid.SubAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		sid.SubAuthorities = append(sid.SubAuthorities, subAuthority)
		offset += size
	}

	return sid
}
