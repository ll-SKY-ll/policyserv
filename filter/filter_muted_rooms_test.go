package filter

import (
	"context"
	"testing"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/policyserv/config"
	"github.com/matrix-org/policyserv/filter/classification"
	"github.com/matrix-org/policyserv/internal"
	"github.com/matrix-org/policyserv/test"
	"github.com/matrix-org/policyserv/trust"
	"github.com/stretchr/testify/assert"
)

const mutedRoomId = "!muted:example.org"
const unmutedRoomId = "!open:example.org"

// makeMutedRoomsSet - builds a Set containing only the muted rooms filter, with power levels and creator trust data
// populated for mutedRoomId.
func makeMutedRoomsSet(t *testing.T, communityConfig *config.CommunityConfig) *Set {
	cnf := &SetConfig{
		CommunityConfig: communityConfig,
		InstanceConfig: &config.InstanceConfig{
			JoinLocalpart:  "policyserv",
			HomeserverName: "policyserv.example.org",
		},
		Groups: []*SetGroupConfig{{
			EnabledNames:           []string{MutedRoomsFilterName},
			MinimumSpamVectorValue: 0.0,
			MaximumSpamVectorValue: 1.0,
		}},
	}
	memStorage := test.NewMemoryStorage(t)
	t.Cleanup(func() { memStorage.Close() })
	ps := test.NewMemoryPubsub(t)
	t.Cleanup(func() { ps.Close() })

	set, err := NewSet(cnf, memStorage, ps, test.MustMakeAuditQueue(5), nil)
	assert.NoError(t, err)
	assert.NotNil(t, set)

	stateKey := ""

	// @mod:codestorm.net is above state_default in the muted room, and is also matched by the deny glob used in the
	// tests below. Power levels must win.
	plSource, err := trust.NewPowerLevelsSource(memStorage)
	assert.NoError(t, err)
	err = plSource.ImportData(context.Background(), mutedRoomId, test.MustMakePDU(&test.BaseClientEvent{
		Type:     "m.room.power_levels",
		StateKey: &stateKey,
		Sender:   "@creator:codestorm.net",
		Content: map[string]any{
			"state_default": 50,
			"users_default": 0,
			"users": map[string]any{
				"@mod:codestorm.net": 100,
			},
		},
	}))
	assert.NoError(t, err)

	// @creator:codestorm.net is a v12 room creator, and is also matched by the deny glob.
	creatorSource, err := trust.NewCreatorSource(memStorage)
	assert.NoError(t, err)
	err = creatorSource.ImportData(context.Background(), mutedRoomId, test.MustMakePDU(&test.BaseClientEvent{
		Type:     "m.room.create",
		StateKey: &stateKey,
		Sender:   "@creator:codestorm.net",
		Content: map[string]any{
			"room_version": "12",
		},
	}))
	assert.NoError(t, err)

	return set
}

func makeMutedRoomsMessage(eventId string, roomId string, sender string) gomatrixserverlib.PDU {
	return test.MustMakePDU(&test.BaseClientEvent{
		EventId: eventId,
		RoomId:  roomId,
		Sender:  sender,
		Type:    "m.room.message",
		Content: map[string]any{
			"msgtype": "m.text",
			"body":    "doesn't matter",
		},
	})
}

// assertMuted - the filter never returns "not spam", so an unmuted event leaves the 0.5 seed value in place.
func assertMuted(t *testing.T, set *Set, event gomatrixserverlib.PDU, isMuted bool) {
	vecs, err := set.CheckEvent(context.Background(), event, nil)
	assert.NoError(t, err)
	if isMuted {
		assert.Equalf(t, 1.0, vecs.GetVector(classification.Spam), "%s should have been muted", event.EventID())
	} else {
		assert.Equalf(t, 0.5, vecs.GetVector(classification.Spam), "%s should not have been muted", event.EventID())
	}
}

func TestMutedRoomsFilterWithGlobs(t *testing.T) {
	t.Parallel()

	// Everyone is allowed, except codestorm.net users. This is the example from the feature request.
	set := makeMutedRoomsSet(t, &config.CommunityConfig{
		MutedRoomsFilterRoomIds:        &[]string{mutedRoomId},
		MutedRoomsFilterAllowedUsers:   &[]string{"@*:*"},
		MutedRoomsFilterDeniedUsers:    &[]string{"@*:codestorm.net"},
		MutedRoomsFilterUsePowerLevels: internal.Pointer(true),
		ModerationBotUserId:            internal.Pointer("@modbot:codestorm.net"),
	})

	// Allow glob matches, so the mute doesn't apply.
	assertMuted(t, set, makeMutedRoomsMessage("$allowed", mutedRoomId, "@someone:example.org"), false)

	// Deny glob overrides the allow glob.
	assertMuted(t, set, makeMutedRoomsMessage("$denied", mutedRoomId, "@spammer:codestorm.net"), true)

	// ... but power levels and room creators beat the deny glob.
	assertMuted(t, set, makeMutedRoomsMessage("$mod", mutedRoomId, "@mod:codestorm.net"), false)
	assertMuted(t, set, makeMutedRoomsMessage("$creator", mutedRoomId, "@creator:codestorm.net"), false)

	// ... as do the hardcoded exemptions, even though both match the deny glob / have no power levels.
	assertMuted(t, set, makeMutedRoomsMessage("$modbot", mutedRoomId, "@modbot:codestorm.net"), false)
	assertMuted(t, set, makeMutedRoomsMessage("$self", mutedRoomId, "@policyserv:policyserv.example.org"), false)

	// Rooms which aren't muted are untouched, even for denied users.
	assertMuted(t, set, makeMutedRoomsMessage("$unmuted", unmutedRoomId, "@spammer:codestorm.net"), false)

	// Membership always passes, regardless of membership value or sender.
	for _, membership := range []string{"join", "leave", "ban", "invite", "knock"} {
		stateKey := "@spammer:codestorm.net"
		assertMuted(t, set, test.MustMakePDU(&test.BaseClientEvent{
			EventId:  "$member_" + membership,
			RoomId:   mutedRoomId,
			Sender:   "@spammer:codestorm.net",
			Type:     "m.room.member",
			StateKey: &stateKey,
			Content: map[string]any{
				"membership": membership,
			},
		}), false)
	}
}

func TestMutedRoomsFilterDeniesByDefault(t *testing.T) {
	t.Parallel()

	// No globs at all: a muted room mutes everyone who isn't otherwise exempt.
	set := makeMutedRoomsSet(t, &config.CommunityConfig{
		MutedRoomsFilterRoomIds:        &[]string{mutedRoomId},
		MutedRoomsFilterUsePowerLevels: internal.Pointer(true),
	})

	assertMuted(t, set, makeMutedRoomsMessage("$nobody", mutedRoomId, "@someone:example.org"), true)
	assertMuted(t, set, makeMutedRoomsMessage("$mod2", mutedRoomId, "@mod:codestorm.net"), false)
	assertMuted(t, set, makeMutedRoomsMessage("$creator2", mutedRoomId, "@creator:codestorm.net"), false)
	assertMuted(t, set, makeMutedRoomsMessage("$self2", mutedRoomId, "@policyserv:policyserv.example.org"), false)

	// Non-membership state events are muted too - a muted room is frozen, not just silenced.
	stateKey := ""
	assertMuted(t, set, test.MustMakePDU(&test.BaseClientEvent{
		EventId:  "$topic",
		RoomId:   mutedRoomId,
		Sender:   "@someone:example.org",
		Type:     "m.room.topic",
		StateKey: &stateKey,
		Content: map[string]any{
			"topic": "doesn't matter",
		},
	}), true)
}

func TestMutedRoomsFilterWithoutPowerLevels(t *testing.T) {
	t.Parallel()

	// With the power levels source disabled, moderators are muted like anyone else.
	set := makeMutedRoomsSet(t, &config.CommunityConfig{
		MutedRoomsFilterRoomIds:        &[]string{mutedRoomId},
		MutedRoomsFilterAllowedUsers:   &[]string{"@*:example.org"},
		MutedRoomsFilterUsePowerLevels: internal.Pointer(false),
	})

	assertMuted(t, set, makeMutedRoomsMessage("$mod3", mutedRoomId, "@mod:codestorm.net"), true)
	assertMuted(t, set, makeMutedRoomsMessage("$creator3", mutedRoomId, "@creator:codestorm.net"), true)
	assertMuted(t, set, makeMutedRoomsMessage("$allowed3", mutedRoomId, "@someone:example.org"), false)
}

func TestMutedRoomsFilterEmptyConfig(t *testing.T) {
	t.Parallel()

	// The filter is normally not enabled at all in this case, but it should be inert if it is.
	set := makeMutedRoomsSet(t, &config.CommunityConfig{
		MutedRoomsFilterRoomIds: &[]string{},
	})

	assertMuted(t, set, makeMutedRoomsMessage("$inert", mutedRoomId, "@someone:example.org"), false)
}
