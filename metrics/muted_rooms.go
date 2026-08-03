package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type MutedRoomOutcome string

// MutedRoomOutcomeMuted - the event was flagged as spam because the room is muted.
const MutedRoomOutcomeMuted MutedRoomOutcome = "muted"

// MutedRoomOutcomeMembership - the event passed because membership events are never muted.
const MutedRoomOutcomeMembership MutedRoomOutcome = "exempt_membership"

// MutedRoomOutcomeConfigured - the event passed because the sender is policyserv itself or the community's
// configured moderation bot.
const MutedRoomOutcomeConfigured MutedRoomOutcome = "exempt_configured"

// MutedRoomOutcomePowerLevels - the event passed because the sender is above state_default or is a room creator.
const MutedRoomOutcomePowerLevels MutedRoomOutcome = "exempt_power_levels"

// MutedRoomOutcomeAllowGlob - the event passed because the sender matched an allow glob.
const MutedRoomOutcomeAllowGlob MutedRoomOutcome = "exempt_allow_glob"

// MutedRoomEvents - Note that this is only incremented for rooms which are actually muted, so the roomId label is
// bounded by the size of the community's muted rooms list rather than by the number of rooms policyserv protects.
var MutedRoomEvents = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "policyserv_muted_room_events",
	Help: "The total number of events seen in muted rooms, by outcome",
}, []string{"roomId", "outcome"})

func RecordMutedRoomEvent(roomId string, outcome MutedRoomOutcome) {
	MutedRoomEvents.With(prometheus.Labels{
		"roomId":  roomId,
		"outcome": string(outcome),
	}).Inc()
}
