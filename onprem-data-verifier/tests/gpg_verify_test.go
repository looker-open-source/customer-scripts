package tests

import (
	"testing"

	"onprem-data-verifier/validator"

	"github.com/stretchr/testify/assert"
)

func TestParseGPGColons(t *testing.T) {
	// 1. Arrange: Input with ONE Primary Key (pub) and ONE Subkey (sub)
	// We want to ensure BOTH are extracted.
	gpgOutput := `
tru::1:1698000000:0:3:1:5
pub:u:2048:1:PRIMARY_KEY_ID:1698000000:::u:::scESC:
uid:u::::1698000000::234567890::Test User <test@example.com>:
sub:u:2048:1:SUBKEY_ID_1234:1698000000:::u:::e:
`

	// 2. Act
	keyIDs, err := validator.ParseGPGColons(gpgOutput)

	// 3. Assert
	assert.NoError(t, err)

	// We expect 2 keys returned (Primary + Subkey)
	assert.Len(t, keyIDs, 2)
	assert.Equal(t, "PRIMARY_KEY_ID", keyIDs[0])
	assert.Equal(t, "SUBKEY_ID_1234", keyIDs[1])
}

func TestParseGPGColons_NotFound(t *testing.T) {
	// 1. Arrange: Output unrelated to keys
	gpgOutput := `
tru::1:1698000000:0:3:1:5
uid:u::::1698000000::234567890::Test User <test@example.com>:
`
	// 2. Act
	keyIDs, err := validator.ParseGPGColons(gpgOutput)

	// 3. Assert
	assert.Error(t, err)
	assert.Nil(t, keyIDs)

	// FIX: Updated expected error text to match source code
	assert.Contains(t, err.Error(), "no keys found in GPG output")
}
