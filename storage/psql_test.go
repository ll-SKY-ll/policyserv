package storage

import (
	"testing"

	"github.com/matrix-org/policyserv/harms"
	"github.com/stretchr/testify/assert"
)

func TestDecodeEventResult(t *testing.T) {
	// It should retain Neutral status
	neutralRes := &StoredEventResult{
		IsProbablySpam: false,
	}
	neutralVecs := `{"spam":0.5}`
	if err := decodeEventResult(neutralRes, neutralVecs); err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, neutralRes.ContentInfo)
	assert.Equal(t, harms.ContentClassNeutral, neutralRes.ContentInfo.Class())

	// It should retain Allowed status
	allowedRes := &StoredEventResult{
		IsProbablySpam: false,
	}
	allowedVecs := `{"Allowed":1.0}`
	if err := decodeEventResult(allowedRes, allowedVecs); err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, allowedRes.ContentInfo)
	assert.Equal(t, harms.ContentClassAllowed, allowedRes.ContentInfo.Class())

	// It should retain Prohibited status
	prohibitedRes := &StoredEventResult{
		IsProbablySpam: true,
	}
	prohibitedVecs := `{}` // doesn't matter - the event is spammy
	if err := decodeEventResult(prohibitedRes, prohibitedVecs); err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, prohibitedRes.ContentInfo)
	assert.Equal(t, harms.ContentClassProhibited, prohibitedRes.ContentInfo.Class())

	// It should retain Prohibited status with harm IDs
	prohibitedRes.ContentInfo = nil // reset for test case
	prohibitedVecs = `{"h:org.matrix.msc4456.spam.fraud":1.0}`
	if err := decodeEventResult(prohibitedRes, prohibitedVecs); err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, prohibitedRes.ContentInfo)
	assert.Equal(t, harms.ContentClassProhibited, prohibitedRes.ContentInfo.Class())
	assert.Equal(t, []harms.Harm{harms.SpamFraud}, prohibitedRes.ContentInfo.Harms())
}
