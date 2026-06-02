package wifi

import "strings"

// validWPAPSK reports whether psk is a valid WPA/WPA2 Personal pre-shared key.
//
// A valid WPA-PSK is either:
//
//   - An 8–63 character passphrase.
//   - A 64-character hexadecimal string (0-9, a-f, A-F) representing
//     the raw 256-bit pre-shared key.
func validWPAPSK(psk string) bool {
	if len(psk) >= 8 && len(psk) <= 63 {
		return true
	}

	if len(psk) == 64 {
		for _, c := range psk {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
		return true
	}

	return false
}

// validSAEPassphrase reports whether passphrase is a valid WPA3-Personal
// SAE password.
//
// Unlike WPA-PSK, SAE accepts passphrases of any length. The only invalid
// value is an empty passphrase.
func validSAEPassphrase(passphrase string) bool {
	return passphrase != ""
}
