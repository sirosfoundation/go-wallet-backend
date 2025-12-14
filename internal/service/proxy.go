package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// ProxyService handles HTTP proxy requests for the wallet
type ProxyService struct {
	client *http.Client
	cfg    *config.Config
	logger *zap.Logger
}

// ProxyRequest represents an incoming proxy request
type ProxyRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Data    interface{}       `json:"data,omitempty"`
}

// ProxyResponse represents the response from a proxied request
type ProxyResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Data    interface{}       `json:"data,omitempty"`
}

// NewProxyService creates a new ProxyService
func NewProxyService(cfg *config.Config, logger *zap.Logger) *ProxyService {
	return &ProxyService{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects - return them to the client
				return http.ErrUseLastResponse
			},
		},
		cfg:    cfg,
		logger: logger.Named("proxy-service"),
	}
}

// binaryExtensionRegex matches common binary file extensions
var binaryExtensionRegex = regexp.MustCompile(`\.(png|jpe?g|gif|webp|bmp|tiff?|ico)(\?.*)?$`)

// IsBinaryRequest checks if the URL points to a binary resource
func IsBinaryRequest(url string) bool {
	return binaryExtensionRegex.MatchString(strings.ToLower(url))
}

// Execute performs the proxy request and returns the response
func (s *ProxyService) Execute(ctx context.Context, req *ProxyRequest) (*ProxyResponse, []byte, error) {
	if req.URL == "" {
		return nil, nil, fmt.Errorf("URL is required")
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	s.logger.Debug("Proxying request",
		zap.String("method", method),
		zap.String("url", req.URL),
	)

	// Build the request body if data is provided
	var bodyReader io.Reader
	if req.Data != nil {
		// Convert data to JSON bytes if it's not already bytes
		switch d := req.Data.(type) {
		case string:
			bodyReader = strings.NewReader(d)
		case []byte:
			bodyReader = bytes.NewReader(d)
		default:
			// For other types, marshal to JSON
			jsonData, err := json.Marshal(d)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to marshal request data: %w", err)
			}
			bodyReader = bytes.NewReader(jsonData)
		}
	}

	// Create the HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Copy headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Execute the request
	resp, err := s.client.Do(httpReq)
	if err != nil {
		s.logger.Error("Proxy request failed", zap.Error(err))
		return &ProxyResponse{
			Status: 504,
			Headers: map[string]string{
				"X-Proxy-Error": err.Error(),
			},
		}, nil, nil
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Convert response headers to map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	isBinary := IsBinaryRequest(req.URL)

	response := &ProxyResponse{
		Status:  resp.StatusCode,
		Headers: headers,
	}

	// For binary responses, return raw bytes
	if isBinary {
		return response, body, nil
	}

	// For text/JSON responses, try to parse as JSON
	if len(body) > 0 {
		var jsonData interface{}
		if err := json.Unmarshal(body, &jsonData); err != nil {
			// Not JSON, return as string
			response.Data = string(body)
		} else {
			response.Data = jsonData
		}
	}

	return response, nil, nil
}
