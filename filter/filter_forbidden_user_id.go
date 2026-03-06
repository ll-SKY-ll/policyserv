package filter

import (
	"context"
	"log"
	"regexp"
	"strings"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/policyserv/filter/classification"
	"github.com/matrix-org/policyserv/internal"
	"github.com/ryanuber/go-glob"
)

const ForbiddenUserIdFilterName = "ForbiddenUserIdFilter"

func init() {
	mustRegister(ForbiddenUserIdFilterName, &ForbiddenUserIdFilter{})
}

type ForbiddenUserIdFilter struct{}

func (f *ForbiddenUserIdFilter) MakeFor(set *Set) (Instanced, error) {
	// Pre-compile denied patterns.
	rawPatterns := internal.Dereference(set.communityConfig.ForbiddenUserIdFilterPatterns)
	compiledRegexes := make([]*regexp.Regexp, 0, len(rawPatterns))
	globPatterns := make([]string, 0, len(rawPatterns))

	for _, pattern := range rawPatterns {
		if len(pattern) > 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
			re, err := regexp.Compile(pattern[1 : len(pattern)-1])
			if err != nil {
				log.Printf("[ForbiddenUserIdFilter] Invalid regex pattern '%s': %s (skipping)", pattern, err)
				continue
			}
			compiledRegexes = append(compiledRegexes, re)
		} else {
			globPatterns = append(globPatterns, pattern)
		}
	}

	// Parse event types: "*" means all, otherwise a list of specific types.
	rawEventTypes := internal.Dereference(set.communityConfig.ForbiddenUserIdFilterEventTypes)
	matchAllEventTypes := false
	eventTypeSet := make(map[string]bool)
	for _, t := range rawEventTypes {
		trimmed := strings.TrimSpace(t)
		if trimmed == "*" {
			matchAllEventTypes = true
			break
		}
		if len(trimmed) > 0 {
			eventTypeSet[trimmed] = true
		}
	}

	// Build allowed user set for whitelist overrides.
	allowedUsers := internal.Dereference(set.communityConfig.ForbiddenUserIdFilterAllowedUsers)
	allowedUserSet := make(map[string]bool, len(allowedUsers))
	for _, u := range allowedUsers {
		allowedUserSet[u] = true
	}

	return &InstancedForbiddenUserIdFilter{
		set:                set,
		globPatterns:       globPatterns,
		compiledRegexes:    compiledRegexes,
		matchAllEventTypes: matchAllEventTypes,
		eventTypeSet:       eventTypeSet,
		allowedUserSet:     allowedUserSet,
	}, nil
}

type InstancedForbiddenUserIdFilter struct {
	set                *Set
	globPatterns       []string
	compiledRegexes    []*regexp.Regexp
	matchAllEventTypes bool
	eventTypeSet       map[string]bool
	allowedUserSet     map[string]bool
}

func (f *InstancedForbiddenUserIdFilter) Name() string {
	return ForbiddenUserIdFilterName
}

func (f *InstancedForbiddenUserIdFilter) CheckEvent(ctx context.Context, input *EventInput) ([]classification.Classification, error) {
	eventType := input.Event.Type()

	// Check if this event type is one we should inspect.
	if !f.matchAllEventTypes && !f.eventTypeSet[eventType] {
		return nil, nil
	}

	// Determine the user ID to check.
	var userId string

	if eventType == spec.MRoomMember {
		// For membership events we need special handling.
		membership, err := input.Event.Membership()
		if err != nil {
			log.Printf("[%s | %s] ForbiddenUserIdFilter: error reading membership: %s", input.Event.EventID(), input.Event.RoomID().String(), err)
			return nil, nil
		}

		// Never block leave events. If the join soft-failed, the leave will too.
		// If the join didn't soft-fail, the leave needs to go through to avoid
		// a diverging room state.
		if membership == spec.Leave {
			return nil, nil
		}

		// For non-leave membership events, check the state_key (target user).
		// But only block if the sender IS the target (self-authored membership change).
		// This ensures admin kicks, bans, and other moderation actions targeting a
		// spammy user ID are never blocked.
		stateKey := input.Event.StateKey()
		if stateKey == nil || len(*stateKey) == 0 {
			return nil, nil
		}

		senderUserId := ""
		uid := input.Event.SenderID().ToUserID()
		if uid != nil {
			senderUserId = uid.String()
		}

		if senderUserId != *stateKey {
			// Sender != target: this is an admin/moderator action (kick, ban, etc.)
			// Always allow these through.
			return nil, nil
		}

		userId = *stateKey
	} else {
		// For all other event types, check the sender.
		uid := input.Event.SenderID().ToUserID()
		if uid == nil {
			return nil, nil
		}
		userId = uid.String()
	}

	// Check whitelist first — allowed users bypass all pattern checks.
	if f.allowedUserSet[userId] {
		return nil, nil
	}

	// Check against glob patterns.
	for _, pattern := range f.globPatterns {
		if glob.Glob(pattern, userId) {
			log.Printf("[%s | %s] ForbiddenUserIdFilter: denied %s from %s (matched glob: %s)", input.Event.EventID(), input.Event.RoomID().String(), eventType, userId, pattern)
			return []classification.Classification{
				classification.Spam,
			}, nil
		}
	}

	// Check against regex patterns.
	for _, re := range f.compiledRegexes {
		if re.MatchString(userId) {
			log.Printf("[%s | %s] ForbiddenUserIdFilter: denied %s from %s (matched regex: %s)", input.Event.EventID(), input.Event.RoomID().String(), eventType, userId, re.String())
			return []classification.Classification{
				classification.Spam,
			}, nil
		}
	}

	return nil, nil
}