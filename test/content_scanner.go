package test

import (
	"context"
	"testing"

	"github.com/matrix-org/policyserv/content"
	"github.com/matrix-org/policyserv/harms"
	"github.com/stretchr/testify/assert"
)

type scanExpectation struct {
	contentType content.Type
	content     []byte
	expected    *harms.ContentInfo
	err         error
}

type MemoryContentScanner struct {
	T *testing.T
	// When true, scans which aren't populated by Expect are allowed rather than rejected as a failed test
	AllowUnexpectedScans bool
	expectations         []scanExpectation
}

func NewMemoryContentScanner(t *testing.T) *MemoryContentScanner {
	return &MemoryContentScanner{T: t}
}

func (m *MemoryContentScanner) Expect(contentType content.Type, content []byte, retInfo *harms.ContentInfo, retErr error) {
	m.expectations = append(m.expectations, scanExpectation{contentType, content, retInfo, retErr})
}

func (m *MemoryContentScanner) Scan(ctx context.Context, contentType content.Type, content []byte) (*harms.ContentInfo, error) {
	assert.NotNil(m.T, ctx, "context is required")

	for _, exp := range m.expectations {
		if exp.contentType == contentType && string(exp.content) == string(content) {
			return exp.expected, exp.err
		}
	}

	if !m.AllowUnexpectedScans {
		assert.Fail(m.T, "unexpected scan")
	}
	return harms.NeutralContent(), nil
}
