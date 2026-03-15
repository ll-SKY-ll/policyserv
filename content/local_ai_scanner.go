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

	"github.com/matrix-org/policyserv/filter/classification"
)

type LocalAIScanner struct {
	apiBaseUrl    string
	nsfwThreshold float64
	nsfwLabel     string
}

type localAIPrediction struct {
	Label string  `json:"label"`
	Score float64 `json:"score"`
}

type localAIResponse struct {
	Predictions []localAIPrediction `json:"predictions"`
}

func NewLocalAIScanner(apiBaseUrl string, nsfwThreshold float64) (*LocalAIScanner, error) {
	if apiBaseUrl == "" {
		return nil, fmt.Errorf("local AI scanner API base URL is required")
	}
	if nsfwThreshold <= 0 || nsfwThreshold > 1 {
		return nil, fmt.Errorf("NSFW threshold must be between 0 and 1, got %f", nsfwThreshold)
	}
	return &LocalAIScanner{
		apiBaseUrl:    apiBaseUrl,
		nsfwThreshold: nsfwThreshold,
		nsfwLabel:     "nsfw",
	}, nil
}

func (s *LocalAIScanner) Scan(ctx context.Context, contentType Type, content []byte) ([]classification.Classification, error) {
	if contentType != TypePhoto {
		log.Printf("[LocalAIScanner] Skipping non-photo content type: %s", contentType)
		return nil, nil
	}

	predictions, err := s.classify(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("local AI classification failed: %w", err)
	}

	for _, p := range predictions {
		if p.Label == s.nsfwLabel && p.Score >= s.nsfwThreshold {
			log.Printf("[LocalAIScanner] NSFW detected (score=%.4f, threshold=%.4f)", p.Score, s.nsfwThreshold)
			return []classification.Classification{classification.Spam}, nil
		}
	}

	log.Printf("[LocalAIScanner] Content appears clean")
	return nil, nil
}

func (s *LocalAIScanner) classify(ctx context.Context, imageBytes []byte) ([]localAIPrediction, error) {
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to %s: %w", reqUrl, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("scanner returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result localAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode scanner response: %w", err)
	}

	return result.Predictions, nil
}
