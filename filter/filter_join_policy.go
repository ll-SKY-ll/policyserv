package filter

import (
	"context"
	"log"
	"regexp"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/policyserv/filter/classification"
	"github.com/matrix-org/policyserv/internal"
	"github.com/ryanuber/go-glob"
)

const JoinPolicyFilterName = "JoinPolicyFilter"

func init() {
	mustRegister(JoinPolicyFilterName, &JoinPolicyFilter{})
}

type JoinPolicyFilter struct{}

func (j *JoinPolicyFilter) MakeFor(set *Set) (Instanced, error) {
	// Pre-compile regex patterns at filter creation time (once per community config change),
	// not at every event check.
	rawPatterns := internal.Dereference(set.communityConfig.JoinPolicyFilterDeniedPatterns)
	compiledRegexes := make([]*regexp.Regexp, 0, len(rawPatterns))
	globPatterns := make([]string, 0, len(rawPatterns))

	for _, pattern := range rawPatterns {
		if len(pattern) > 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
			// Treat /pattern/ as regex
			re, err := regexp.Compile(pattern[1 : len(pattern)-1])
			if err != nil {
				log.Printf("[JoinPolicyFilter] Invalid regex pattern '%s': %s (skipping)", pattern, err)
				continue
			}
			compiledRegexes = append(compiledRegexes, re)
		} else {
			// Treat everything else as a glob
			globPatterns = append(globPatterns, pattern)
		}
	}

	return &InstancedJoinPolicyFilter{
		set:             set,
		globPatterns:    globPatterns,
		compiledRegexes: compiledRegexes,
	}, nil
}

type InstancedJoinPolicyFilter struct {
	set             *Set
	globPatterns    []string
	compiledRegexes []*regexp.Regexp
}

func (f *InstancedJoinPolicyFilter) Name() string {
	return JoinPolicyFilterName
}

func (f *InstancedJoinPolicyFilter) CheckEvent(ctx context.Context, input *EventInput) ([]classification.Classification, error) {
	// Only process m.room.member join events
	if input.Event.Type() != spec.MRoomMember {
		return nil, nil
	}

	membership, err := input.Event.Membership()
	if err != nil {
		log.Printf("[%s | %s] JoinPolicyFilter: error reading membership: %s", input.Event.EventID(), input.Event.RoomID().String(), err)
		return nil, nil // non-fatal: skip rather than block
	}
	if membership != spec.Join {
		return nil, nil // only interested in joins
	}

	// The state_key of a membership event is the user ID being affected
	stateKey := input.Event.StateKey()
	if stateKey == nil || len(*stateKey) == 0 {
		return nil, nil
	}
	userId := *stateKey

	// Check against glob patterns
	for _, pattern := range f.globPatterns {
		if glob.Glob(pattern, userId) {
			log.Printf("[%s | %s] JoinPolicyFilter: denied join from %s (matched glob: %s)", input.Event.EventID(), input.Event.RoomID().String(), userId, pattern)
			return []classification.Classification{
				classification.Spam,
			}, nil
		}
	}

	// Check against compiled regex patterns
	for _, re := range f.compiledRegexes {
		if re.MatchString(userId) {
			log.Printf("[%s | %s] JoinPolicyFilter: denied join from %s (matched regex: %s)", input.Event.EventID(), input.Event.RoomID().String(), userId, re.String())
			return []classification.Classification{
				classification.Spam,
			}, nil
		}
	}

	return nil, nil
}