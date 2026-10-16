package filter

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/policyserv/harms"
	"github.com/matrix-org/policyserv/internal"
	"github.com/matrix-org/policyserv/metrics"
	"github.com/matrix-org/policyserv/trust"
)

// Developer note: this filter is intended to run in its own set group *after* the hellban postfilter group, checking
// neutral and allowed content.
//
// HellbanPostfilter runs on any event which an earlier group marked as prohibited, and assumes that event is spam. If
// the mute ran in any group before it, a user who innocently sends a message to a muted room (mutes are not visible to
// clients) would get hellbanned across the entire community, and re-hellbanned on every retry after the previous one
// expired. Running after the hellban group makes that structurally impossible rather than conditionally avoided.
//
// Allowed content is checked too, so the sender and event type allowlists can't bypass a mute.
//
// The cost of this placement is that muted rooms still run the full middle filter group (media downloads, HMA, local
// AI scanners, OpenAI). That's deliberate: it keeps real harms (csam, etc.) flowing into the audit trail for muted
// rooms instead of collapsing everything to "spam, because muted".

const MutedRoomsFilterName = "MutedRoomsFilter"

func init() {
	mustRegister(MutedRoomsFilterName, &MutedRoomsFilter{})
}

type MutedRoomsFilter struct{}

func (f *MutedRoomsFilter) MakeFor(set *Set) (Instanced, error) {
	// Room IDs are matched exactly. Globs are deliberately not supported here: v12+ room IDs have no `:server`
	// suffix (MSC4291), so glob semantics would differ between room versions in surprising ways.
	mutedRooms := make(map[string]bool)
	for _, roomId := range internal.Dereference(set.communityConfig.MutedRoomsFilterRoomIds) {
		trimmed := strings.TrimSpace(roomId)
		if len(trimmed) > 0 {
			mutedRooms[trimmed] = true
		}
	}

	// The community's own allow/deny globs. The deny list wins over the allow list within this source.
	globSource, err := trust.NewSelfDirectedSource(
		set.storage,
		internal.Dereference(set.communityConfig.MutedRoomsFilterAllowedUsers),
		internal.Dereference(set.communityConfig.MutedRoomsFilterDeniedUsers),
	)
	if err != nil {
		return nil, err
	}

	// Privileged sources are checked *before* the globs so that the deny list can never mute a moderator or a room
	// creator. Note that this is intentionally different from UntrustedMediaFilter, which runs all of its sources in
	// a single loop where any deny short-circuits the remaining sources.
	privilegedSources := make([]trust.Source, 0, 2)
	if internal.Dereference(set.communityConfig.MutedRoomsFilterUsePowerLevels) {
		creatorSource, err := trust.NewCreatorSource(set.storage)
		if err != nil {
			return nil, err
		}
		plSource, err := trust.NewPowerLevelsSource(set.storage)
		if err != nil {
			return nil, err
		}
		privilegedSources = append(privilegedSources, creatorSource, plSource)
	}

	// Hardcoded exemptions which the deny list cannot override: our own user (so we can still join, rejoin, and
	// manage state in a muted room) and the community's moderation bot. The moderation bot exemption is a backstop
	// for the window before the room's power levels have been learned, where the power levels source has no data
	// and would otherwise let the mute apply to the bot.
	alwaysAllowed := make(map[string]bool)
	if set.instanceConfig != nil && set.instanceConfig.JoinLocalpart != "" && set.instanceConfig.HomeserverName != "" {
		localUserId := fmt.Sprintf("@%s:%s", set.instanceConfig.JoinLocalpart, set.instanceConfig.HomeserverName)
		alwaysAllowed[localUserId] = true
	}
	if modBotUserId := internal.Dereference(set.communityConfig.ModerationBotUserId); modBotUserId != "" {
		alwaysAllowed[modBotUserId] = true
	}

	return &InstancedMutedRoomsFilter{
		set:               set,
		mutedRooms:        mutedRooms,
		alwaysAllowed:     alwaysAllowed,
		privilegedSources: privilegedSources,
		globSource:        globSource,
	}, nil
}

type InstancedMutedRoomsFilter struct {
	set               *Set
	mutedRooms        map[string]bool
	alwaysAllowed     map[string]bool
	privilegedSources []trust.Source
	globSource        trust.Source
}

func (f *InstancedMutedRoomsFilter) Name() string {
	return MutedRoomsFilterName
}

func (f *InstancedMutedRoomsFilter) CheckEvent(ctx context.Context, input *EventInput) (*harms.ContentInfo, error) {
	roomId := input.Event.RoomID().String()
	if !f.mutedRooms[roomId] {
		return harms.NeutralContent(), nil // the room isn't muted, so we have no opinion on the event
	}

	// Membership events always pass. Muting a leave traps the user in the room and diverges room state, and muting
	// joins, kicks, or bans would stop people (and moderators) from managing membership in a room where they have no
	// way of knowing the mute exists.
	if input.Event.Type() == spec.MRoomMember {
		metrics.RecordMutedRoomEvent(roomId, metrics.MutedRoomOutcomeMembership)
		return harms.NeutralContent(), nil
	}

	uid := input.Event.SenderID().ToUserID()
	if uid == nil {
		return harms.NeutralContent(), nil // Set.CheckEvent already flags these events, so there's nothing useful to add
	}
	userId := uid.String()

	if f.alwaysAllowed[userId] {
		log.Printf("[%s | %s] MutedRoomsFilter: %s is exempt from the mute", input.Event.EventID(), roomId, userId)
		metrics.RecordMutedRoomEvent(roomId, metrics.MutedRoomOutcomeConfigured)
		return harms.NeutralContent(), nil
	}

	// Power levels and room creators beat the deny list.
	for _, source := range f.privilegedSources {
		has, err := source.HasCapability(ctx, userId, roomId, trust.CapabilitySpeak)
		if err != nil {
			return nil, err
		}
		if has == trust.TristateTrue {
			log.Printf("[%s | %s] MutedRoomsFilter: %T exempts %s from the mute", input.Event.EventID(), roomId, source, userId)
			metrics.RecordMutedRoomEvent(roomId, metrics.MutedRoomOutcomePowerLevels)
			return harms.NeutralContent(), nil
		}
	}

	// Finally, the community's own globs. A deny match returns TristateFalse, which falls through to the mute below,
	// as does having no opinion at all - a muted room denies by default.
	has, err := f.globSource.HasCapability(ctx, userId, roomId, trust.CapabilitySpeak)
	if err != nil {
		return nil, err
	}
	if has == trust.TristateTrue {
		metrics.RecordMutedRoomEvent(roomId, metrics.MutedRoomOutcomeAllowGlob)
		return harms.NeutralContent(), nil
	}

	log.Printf("[%s | %s] MutedRoomsFilter: muted %s from %s", input.Event.EventID(), roomId, input.Event.Type(), userId)
	metrics.RecordMutedRoomEvent(roomId, metrics.MutedRoomOutcomeMuted)
	return harms.ProhibitedContent(harms.SpamGeneral), nil
}
