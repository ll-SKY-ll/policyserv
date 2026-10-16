package content

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"

	"github.com/matrix-org/policyserv/harms"
)

// LocalAIScannerDef defines an available scanner at the instance level.
// The type is a unique identifier (e.g. "nsfw", "violence"), the URL
// is the base URL of the scanner service, and Harms are the harm IDs
// reported when the scanner flags content.
type LocalAIScannerDef struct {
	Type  string
	Url   string
	Harms []harms.Harm
}

// LocalAIScannerCommunityConfig defines a community's opt-in to a specific
// scanner type with their chosen threshold.
type LocalAIScannerCommunityConfig struct {
	Type      string  `json:"type"`
	Threshold float64 `json:"threshold"`
}

// LocalAIScanner implements Scanner by calling a local HTTP-based image
// classification service. It is configured with a scanner type, URL, and
// threshold. Each instance targets one scanner service.
type LocalAIScanner struct {
	scannerType string
	apiBaseUrl  string
	threshold   float64
	harms       []harms.Harm
}

type localAIScanResponse struct {
	Model     string  `json:"model"`
	FlagLabel string  `json:"flag_label"`
	Score     float64 `json:"score"`
	Flagged   bool    `json:"flagged"`
}

// NewLocalAIScanner creates a scanner targeting a specific scanner service.
// The threshold is the minimum score to trigger a positive classification.
func NewLocalAIScanner(scannerType string, apiBaseUrl string, threshold float64, harmIds []harms.Harm) (*LocalAIScanner, error) {
	if apiBaseUrl == "" {
		return nil, fmt.Errorf("local AI scanner URL is required for type %q", scannerType)
	}
	if threshold <= 0 || threshold > 1 {
		return nil, fmt.Errorf("threshold for scanner %q must be between 0 and 1, got %f", scannerType, threshold)
	}
	return &LocalAIScanner{
		scannerType: scannerType,
		apiBaseUrl:  apiBaseUrl,
		threshold:   threshold,
		harms:       harmIds,
	}, nil
}

func (s *LocalAIScanner) Scan(ctx context.Context, contentType Type, content []byte) (*harms.ContentInfo, error) {
	if contentType != TypePhoto {
		log.Printf("[LocalAIScanner:%s] Skipping non-photo content type: %s", s.scannerType, contentType)
		return harms.NeutralContent(), nil
	}

	resp, err := s.classify(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("[LocalAIScanner:%s] classification failed: %w", s.scannerType, err)
	}

	if resp.Score >= s.threshold {
		log.Printf("[LocalAIScanner:%s] Flagged (score=%.4f, threshold=%.4f, model=%s)", s.scannerType, resp.Score, s.threshold, resp.Model)
		return harms.ProhibitedContent(append([]harms.Harm{harms.PolicyservMedia}, s.harms...)...), nil
	}

	log.Printf("[LocalAIScanner:%s] Clean (score=%.4f, threshold=%.4f)", s.scannerType, resp.Score, s.threshold)
	return harms.NeutralContent(), nil
}

func (s *LocalAIScanner) classify(ctx context.Context, imageBytes []byte) (*localAIScanResponse, error) {
	buf := &bytes.Buffer{}
	writer := multipart.NewWriter(buf)
	part, err := writer.CreateFormFile("file", "image")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}
	_, err = part.Write(imageBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write image to form: %w", err)
	}
	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	reqUrl := s.apiBaseUrl + "/scan"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqUrl, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to %s: %w", reqUrl, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("scanner returned HTTP %d: %s", httpResp.StatusCode, string(body))
	}

	var result localAIScanResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode scanner response: %w", err)
	}

	return &result, nil
}

// ParseLocalAIScannerDefs parses the instance-level scanner definitions from
// the env var format: "type|url|harm;harm,type|url|harm"
// e.g. "nsfw|http://127.0.0.1:5000|org.matrix.msc4456.adult,violence|http://127.0.0.1:5001|org.matrix.msc4456.violence.graphic"
// The harm list is optional; without it, flagged content is reported as org.matrix.msc4456.other.
func ParseLocalAIScannerDefs(raw string) ([]LocalAIScannerDef, error) {
	if raw == "" {
		return nil, nil
	}

	var defs []LocalAIScannerDef
	for _, entry := range splitAndTrim(raw, ",") {
		parts := splitAndTrim(entry, "|")
		if len(parts) != 2 && len(parts) != 3 {
			return nil, fmt.Errorf("invalid scanner definition %q: expected type|url or type|url|harms", entry)
		}
		harmIds := make([]harms.Harm, 0)
		if len(parts) == 3 {
			for _, h := range splitAndTrim(parts[2], ";") {
				harmIds = append(harmIds, harms.Harm(h))
			}
		}
		defs = append(defs, LocalAIScannerDef{
			Type:  parts[0],
			Url:   parts[1],
			Harms: harmIds,
		})
	}
	return defs, nil
}

func splitAndTrim(s string, sep string) []string {
	var result []string
	for _, part := range bytes.Split([]byte(s), []byte(sep)) {
		trimmed := bytes.TrimSpace(part)
		if len(trimmed) > 0 {
			result = append(result, string(trimmed))
		}
	}
	return result
}
