package content

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/matrix-org/policyserv/filter/classification"
)

type MultiScanner struct {
	scanners []Scanner
}

func NewMultiScanner(scanners ...Scanner) *MultiScanner {
	return &MultiScanner{scanners: scanners}
}

func (m *MultiScanner) Scan(ctx context.Context, contentType Type, content []byte) ([]classification.Classification, error) {
	var allErrors []error

	for i, scanner := range m.scanners {
		results, err := scanner.Scan(ctx, contentType, content)
		if err != nil {
			log.Printf("[MultiScanner] Scanner %d returned error: %s", i, err)
			allErrors = append(allErrors, fmt.Errorf("scanner %d: %w", i, err))
			continue
		}
		if len(results) > 0 {
			log.Printf("[MultiScanner] Scanner %d flagged content: %v", i, results)
			return results, nil
		}
	}

	if len(allErrors) == len(m.scanners) {
		return nil, errors.Join(allErrors...)
	}

	return nil, nil
}
