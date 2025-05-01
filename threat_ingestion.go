package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/bigquery"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/joho/godotenv"
	"google.golang.org/api/option"
)

// Configuration constants
var (
	ProjectID        string
	DatasetID        string
	Environment      string
	Region           string
	APIKey           string
	SecretPrefix     string
	GCSBucket        string
	RequestTimeout   = 30 * time.Second
	APIAuthEnabled   bool
	FeedRefreshLimit = 5 * time.Minute // Limit how often feeds can be refreshed
)

// Track when feeds were last refreshed
var (
	lastRefreshTimes = make(map[string]time.Time)
	refreshMutex     sync.Mutex
)

// FeedSource represents a threat feed configuration
type FeedSource struct {
	URL         string `json:"url"`
	TableID     string `json:"table_id"`
	Format      string `json:"format"`
	Description string `json:"description"`
	SkipLines   int    `json:"skip_lines,omitempty"`
	APIKey      string `json:"api_key,omitempty"`
}

// FeedSources maps feed names to their configurations
var FeedSources = map[string]FeedSource{
	"threatfox": {
		URL:         "https://threatfox.abuse.ch/export/json/recent/",
		TableID:     "threatfox_iocs",
		Format:      "json",
		Description: "ThreatFox IOCs - Malware indicators database",
	},
	"phishtank": {
		URL:         "https://data.phishtank.com/data/online-valid.json",
		TableID:     "phishtank_urls",
		Format:      "json",
		Description: "PhishTank - Community-verified phishing URLs",
	},
	"urlhaus": {
		URL:         "https://urlhaus.abuse.ch/downloads/csv_recent/",
		TableID:     "urlhaus_malware",
		Format:      "csv",
		SkipLines:   8,
		Description: "URLhaus - Database of malicious URLs",
	},
	"feodotracker": {
		URL:         "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
		TableID:     "feodotracker_c2",
		Format:      "csv",
		SkipLines:   8,
		Description: "Feodo Tracker - Botnet C2 IP Blocklist",
	},
}

// IOCPatterns contains regex patterns for extracting IOCs
var IOCPatterns = map[string]*regexp.Regexp{
	"ip":      regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	"domain":  regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b`),
	"url":     regexp.MustCompile(`https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[-\w%/.]*)*`),
	"md5":     regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`),
	"sha1":    regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`),
	"sha256":  regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`),
	"email":   regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
	"cve":     regexp.MustCompile(`CVE-\d{4}-\d{4,7}`),
}

// ThreatIOC represents an indicator of compromise
type ThreatIOC struct {
	Type       string                 `json:"type"`
	Value      string                 `json:"value"`
	Source     string                 `json:"source"`
	Confidence int                    `json:"confidence"`
	FirstSeen  string                 `json:"first_seen"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ProcessResult represents the result of processing a feed
type ProcessResult struct {
	FeedName     string    `json:"feed_name"`
	Status       string    `json:"status"`
	Message      string    `json:"message,omitempty"`
	RecordCount  int       `json:"record_count"`
	Duration     float64   `json:"duration_seconds,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	AnalysisData string    `json:"analysis,omitempty"`
}

// Initialize loads environment variables and sets up configuration
func Initialize() {
	// Load environment from .env file if present
	godotenv.Load()

	// Set configuration from environment variables
	ProjectID = getEnv("GCP_PROJECT", "")
	DatasetID = getEnv("BIGQUERY_DATASET", "threat_intelligence")
	Environment = getEnv("ENVIRONMENT", "development")
	Region = getEnv("GCP_REGION", "us-central1")
	APIKey = getEnv("API_KEY", "")
	GCSBucket = getEnv("GCS_BUCKET", "")
	SecretPrefix = getEnv("SECRET_PREFIX", "projects/"+ProjectID+"/secrets/")

	// Attempt to determine project ID if not explicitly set
	if ProjectID == "" {
		// Try to get from GCP metadata
		ProjectID = getProjectIDFromMetadata()
		if ProjectID == "" {
			// Use a fallback value
			ProjectID = "primal-chariot-382610"
			log.Printf("Warning: Unable to determine GCP project ID. Using fallback: %s", ProjectID)
		}
	}

	// Try creating a bucket name if not specified
	if GCSBucket == "" {
		GCSBucket = fmt.Sprintf("%s-threat-data", ProjectID)
	}

	// Enable API authentication if in production
	APIAuthEnabled = Environment == "production" && APIKey != ""

	log.Printf("Initialized Go Threat Ingestion Module with project: %s, dataset: %s, env: %s, region: %s",
		ProjectID, DatasetID, Environment, Region)

	// OTX integration if key is available
	otxKey := getEnv("OTX_API_KEY", "")
	if otxKey != "" {
		FeedSources["otx_alienvault"] = FeedSource{
			URL:         "https://otx.alienvault.com/api/v1/pulses/subscribed",
			TableID:     "otx_alienvault",
			Format:      "json",
			APIKey:      otxKey,
			Description: "OTX AlienVault - Threat intelligence from Open Threat Exchange",
		}
		log.Printf("OTX AlienVault feed configured with API key")
	}

	// Load additional feeds from Secret Manager (if available)
	loadFeedConfigFromSecrets()
}

// getProjectIDFromMetadata attempts to get the project ID from GCP metadata server
func getProjectIDFromMetadata() string {
	client := &http.Client{Timeout: 1 * time.Second}
	req, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/project/project-id", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

// loadFeedConfigFromSecrets loads feed configurations from Secret Manager
func loadFeedConfigFromSecrets() {
	if Environment != "production" {
		return
	}

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Printf("Failed to create Secret Manager client: %v", err)
		return
	}
	defer client.Close()

	secretName := fmt.Sprintf("%sfeed-config", SecretPrefix)
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName + "/latest",
	}

	resp, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		log.Printf("Failed to access feed-config secret: %v", err)
		return
	}

	var feedConfig map[string]FeedSource
	if err := json.Unmarshal(resp.Payload.Data, &feedConfig); err != nil {
		log.Printf("Failed to parse feed config: %v", err)
		return
	}

	// Merge with existing feeds
	for name, config := range feedConfig {
		FeedSources[name] = config
		log.Printf("Loaded feed configuration for %s from Secret Manager", name)
	}
}

// getEnv reads an environment variable with a default fallback
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// HTTPHandler handles HTTP requests for data ingestion
func HTTPHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	log.Printf("Received ingestion request from %s", r.RemoteAddr)

	// Check authentication if enabled
	if APIAuthEnabled {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Also check query parameters
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey != APIKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("Unauthorized request from %s", r.RemoteAddr)
			return
		}
	}

	// Only allow POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var requestData struct {
		FeedName   string `json:"feed_name"`
		ProcessAll bool   `json:"process_all"`
		Force      bool   `json:"force"`
		FileType   string `json:"file_type"`
		Content    string `json:"content"`
		Command    string `json:"command"`
	}

	// Check if it's a health check command
	if r.Method == http.MethodPost && r.ContentLength > 0 {
		err := json.NewDecoder(r.Body).Decode(&requestData)
		if err != nil {
			log.Printf("Error decoding request: %v", err)
			requestData.ProcessAll = true // Default to processing all if parsing fails
		}
		
		// Handle health check command
		if requestData.Command == "health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "ok",
				"version":     "1.0.0",
				"environment": Environment,
				"project_id":  ProjectID,
				"region":      Region,
				"timestamp":   time.Now().Format(time.RFC3339),
			})
			return
		}
	}

	// Log request duration at the end
	defer func() {
		log.Printf("Request completed in %v", time.Since(startTime))
	}()

	// Handle CSV upload if specified
	if requestData.FileType == "csv" && requestData.Content != "" {
		feedName := requestData.FeedName
		if feedName == "" {
			feedName = "csv_upload"
		}

		result, err := analyzeCSVFile(requestData.Content, feedName)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error analyzing CSV: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	// Process specific feed or all feeds
	var results []ProcessResult
	if requestData.FeedName != "" && requestData.FeedName != "all" {
		// Check if this feed was recently refreshed (unless forced)
		if !requestData.Force && !canRefreshFeed(requestData.FeedName) {
			lastRefresh := lastRefreshTimes[requestData.FeedName]
			timeUntilRefresh := FeedRefreshLimit - time.Since(lastRefresh)
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"feed_name": requestData.FeedName,
				"status":    "rate_limited",
				"message":   fmt.Sprintf("Feed was refreshed recently. Please wait %v before refreshing again.", timeUntilRefresh.Round(time.Second)),
				"timestamp": time.Now(),
			})
			return
		}

		result, err := processFeed(requestData.FeedName)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error processing feed: %v", err), http.StatusInternalServerError)
			return
		}
		results = append(results, result)
	} else {
		results, err := processAllFeeds(requestData.Force)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error processing feeds: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"results": results,
			"count":   len(results),
		})
		return
	}

	// Return results
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"results": results,
		"count":   len(results),
	})
}

// canRefreshFeed checks if enough time has passed since the last refresh
func canRefreshFeed(feedName string) bool {
	refreshMutex.Lock()
	defer refreshMutex.Unlock()

	lastRefresh, exists := lastRefreshTimes[feedName]
	if !exists {
		return true
	}

	return time.Since(lastRefresh) >= FeedRefreshLimit
}

// updateRefreshTime updates the last refresh time for a feed
func updateRefreshTime(feedName string) {
	refreshMutex.Lock()
	defer refreshMutex.Unlock()
	lastRefreshTimes[feedName] = time.Now()
}

// processAllFeeds processes all configured feeds
func processAllFeeds(force bool) ([]ProcessResult, error) {
	var results []ProcessResult
	var wg sync.WaitGroup
	resultChan := make(chan ProcessResult, len(FeedSources))
	errorChan := make(chan error, len(FeedSources))

	for feedName := range FeedSources {
		// Skip feeds that were recently refreshed (unless forced)
		if !force && !canRefreshFeed(feedName) {
			log.Printf("Skipping feed %s due to rate limiting", feedName)
			lastRefresh := lastRefreshTimes[feedName]
			timeUntilRefresh := FeedRefreshLimit - time.Since(lastRefresh)
			
			resultChan <- ProcessResult{
				FeedName:  feedName,
				Status:    "rate_limited",
				Message:   fmt.Sprintf("Feed was refreshed recently. Please wait %v before refreshing again.", timeUntilRefresh.Round(time.Second)),
				Timestamp: time.Now(),
			}
			continue
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			result, err := processFeed(name)
			if err != nil {
				log.Printf("Error processing feed %s: %v", name, err)
				errorChan <- err
				resultChan <- ProcessResult{
					FeedName:  name,
					Status:    "error",
					Message:   err.Error(),
					Timestamp: time.Now(),
				}
				return
			}
			resultChan <- result
		}(feedName)

		// Small delay to avoid overwhelming APIs
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultChan)
	close(errorChan)

	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}

	// Check for errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		log.Printf("%d feeds had errors during processing", len(errors))
	}

	return results, nil
}

// processFeed processes a specific feed
func processFeed(feedName string) (ProcessResult, error) {
	startTime := time.Now()
	log.Printf("Processing feed: %s", feedName)

	// Verify feed exists
	feedConfig, exists := FeedSources[feedName]
	if !exists {
		return ProcessResult{
			FeedName:  feedName,
			Status:    "error",
			Message:   "Unknown feed",
			Timestamp: time.Now(),
		}, fmt.Errorf("unknown feed: %s", feedName)
	}

	// Generate unique ingestion ID
	ingestionID := fmt.Sprintf("%s_%s", feedName, time.Now().Format("20060102150405"))

	// Fetch data from feed
	client := &http.Client{
		Timeout: RequestTimeout,
	}

	req, err := http.NewRequest("GET", feedConfig.URL, nil)
	if err != nil {
		return ProcessResult{
			FeedName:  feedName,
			Status:    "error",
			Message:   fmt.Sprintf("Error creating request: %v", err),
			Timestamp: time.Now(),
		}, err
	}

	// Add API key header if needed
	if feedConfig.APIKey != "" {
		if feedName == "otx_alienvault" {
			req.Header.Add("X-OTX-API-KEY", feedConfig.APIKey)
		} else {
			req.Header.Add("Authorization", "Bearer "+feedConfig.APIKey)
		}
	}

	// Execute request with retries
	var resp *http.Response
	var content []byte
	maxRetries := 3

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			content, err = io.ReadAll(resp.Body)
			if err == nil && len(content) > 0 {
				break
			}
		}

		if resp != nil {
			resp.Body.Close()
		}

		if attempt < maxRetries-1 {
			delay := time.Duration(2*attempt+1) * time.Second
			log.Printf("Retrying feed %s in %v (attempt %d/%d)", feedName, delay, attempt+1, maxRetries)
			time.Sleep(delay)
		}
	}

	if err != nil || len(content) == 0 {
		return ProcessResult{
			FeedName:  feedName,
			Status:    "error",
			Message:   fmt.Sprintf("Error fetching feed: %v", err),
			Timestamp: time.Now(),
		}, fmt.Errorf("error fetching feed: %v", err)
	}

	log.Printf("Received %d bytes from %s", len(content), feedConfig.URL)

	// Process based on format
	var records []map[string]interface{}
	var processErr error

	switch feedConfig.Format {
	case "json":
		records, processErr = processJSONFeed(feedName, content, ingestionID, feedConfig)
	case "csv":
		records, processErr = processCSVFeed(feedName, string(content), ingestionID, feedConfig)
	default:
		return ProcessResult{
			FeedName:  feedName,
			Status:    "error",
			Message:   fmt.Sprintf("Unsupported format: %s", feedConfig.Format),
			Timestamp: time.Now(),
		}, fmt.Errorf("unsupported format: %s", feedConfig.Format)
	}

	if processErr != nil {
		return ProcessResult{
			FeedName:  feedName,
			Status:    "error",
			Message:   fmt.Sprintf("Error processing feed: %v", processErr),
			Timestamp: time.Now(),
		}, processErr
	}

	if len(records) == 0 {
		return ProcessResult{
			FeedName:  feedName,
			Status:    "warning",
			Message:   "No records extracted",
			Timestamp: time.Now(),
		}, nil
	}

	// Insert into BigQuery
	log.Printf("Inserting %d records into %s", len(records), feedConfig.TableID)
	insertedCount, err := insertIntoBigQuery(feedConfig.TableID, records)
	if err != nil {
		return ProcessResult{
			FeedName:  feedName,
			Status:    "error",
			Message:   fmt.Sprintf("Error inserting into BigQuery: %v", err),
			Timestamp: time.Now(),
		}, err
	}

	// Extract and store IOCs
	iocs, err := extractIOCs(records, feedName)
	if err != nil {
		log.Printf("Warning: Error extracting IOCs: %v", err)
	}

	var analysisData string
	if len(iocs) > 0 {
		analysisResult, err := createAnalysisEntry(feedName, records, iocs, ingestionID)
		if err != nil {
			log.Printf("Warning: Error creating analysis entry: %v", err)
		} else {
			analysisData = analysisResult
		}
	}

	// Update the last refresh time
	updateRefreshTime(feedName)

	// Calculate duration
	duration := time.Since(startTime).Seconds()

	return ProcessResult{
		FeedName:     feedName,
		Status:       "success",
		RecordCount:  insertedCount,
		Duration:     duration,
		Timestamp:    time.Now(),
		AnalysisData: analysisData,
	}, nil
}

// processJSONFeed processes JSON feed data
func processJSONFeed(feedName string, content []byte, ingestionID string, feedConfig FeedSource) ([]map[string]interface{}, error) {
	var records []map[string]interface{}
	timestamp := time.Now().Format(time.RFC3339)

	// Parse JSON based on feed structure
	switch feedName {
	case "threatfox":
		var data map[string]interface{}
		err := json.Unmarshal(content, &data)
		if err != nil {
			return nil, fmt.Errorf("error parsing JSON: %v", err)
		}

		// ThreatFox has a specific structure with data array
		if dataArray, ok := data["data"].([]interface{}); ok {
			for _, item := range dataArray {
				if record, ok := item.(map[string]interface{}); ok {
					// Add standard metadata
					record["_ingestion_timestamp"] = timestamp
					record["_ingestion_id"] = ingestionID
					record["_source"] = feedName
					record["_feed_type"] = feedConfig.Description
					records = append(records, record)
				}
			}
		}

	case "phishtank":
		var data []interface{}
		err := json.Unmarshal(content, &data)
		if err != nil {
			return nil, fmt.Errorf("error parsing JSON: %v", err)
		}

		// PhishTank is a simple array
		for _, item := range data {
			if record, ok := item.(map[string]interface{}); ok {
				// Add standard metadata
				record["_ingestion_timestamp"] = timestamp
				record["_ingestion_id"] = ingestionID
				record["_source"] = feedName
				record["_feed_type"] = feedConfig.Description
				records = append(records, record)
			}
		}

	case "otx_alienvault":
		var data map[string]interface{}
		err := json.Unmarshal(content, &data)
		if err != nil {
			return nil, fmt.Errorf("error parsing JSON: %v", err)
		}

		// OTX has a results array
		if results, ok := data["results"].([]interface{}); ok {
			for _, item := range results {
				if pulse, ok := item.(map[string]interface{}); ok {
					// Add standard metadata
					pulse["_ingestion_timestamp"] = timestamp
					pulse["_ingestion_id"] = ingestionID
					pulse["_source"] = feedName
					pulse["_feed_type"] = feedConfig.Description
					records = append(records, pulse)
				}
			}
		}

	default:
		// Generic JSON handling
		var data interface{}
		err := json.Unmarshal(content, &data)
		if err != nil {
			return nil, fmt.Errorf("error parsing JSON: %v", err)
		}

		// Process based on top-level structure
		switch v := data.(type) {
		case []interface{}:
			for _, item := range v {
				if record, ok := item.(map[string]interface{}); ok {
					// Add standard metadata
					record["_ingestion_timestamp"] = timestamp
					record["_ingestion_id"] = ingestionID
					record["_source"] = feedName
					record["_feed_type"] = feedConfig.Description
					records = append(records, record)
				}
			}
		case map[string]interface{}:
			// Look for arrays within the object
			for _, value := range v {
				if items, ok := value.([]interface{}); ok {
					for _, item := range items {
						if record, ok := item.(map[string]interface{}); ok {
							// Add standard metadata
							record["_ingestion_timestamp"] = timestamp
							record["_ingestion_id"] = ingestionID
							record["_source"] = feedName
							record["_feed_type"] = feedConfig.Description
							records = append(records, record)
						}
					}
				}
			}
		}
	}

	log.Printf("Extracted %d records from %s JSON feed", len(records), feedName)
	return records, nil
}

// processCSVFeed processes CSV feed data
func processCSVFeed(feedName string, content string, ingestionID string, feedConfig FeedSource) ([]map[string]interface{}, error) {
	var records []map[string]interface{}
	timestamp := time.Now().Format(time.RFC3339)

	// Handle special feed processing
	if feedName == "urlhaus" || feedName == "feodotracker" {
		// URLhaus CSV has a comment header that starts with #
		// Find the actual CSV header line (first non-comment line)
		lines := strings.Split(content, "\n")
		headerLineIndex := -1

		for i, line := range lines {
			if line != "" && !strings.HasPrefix(line, "#") {
				headerLineIndex = i
				break
			}
		}

		if headerLineIndex >= 0 {
			// Extract headers and content lines
			headers := strings.Split(lines[headerLineIndex], ",")
			for i := range headers {
				headers[i] = strings.Trim(headers[i], "\"")
			}

			// Process content lines
			for i := headerLineIndex + 1; i < len(lines); i++ {
				line := lines[i]
				if line == "" {
					continue
				}

				// Split CSV line (handling quoted values)
				parts := parseCSVLine(line)
				if len(parts) == 0 {
					continue
				}

				// Create record
				record := make(map[string]interface{})
				for j, part := range parts {
					if j < len(headers) {
						record[headers[j]] = part
					}
				}

				// Add standard metadata
				record["_ingestion_timestamp"] = timestamp
				record["_ingestion_id"] = ingestionID
				record["_source"] = feedName
				record["_feed_type"] = feedConfig.Description

				records = append(records, record)
			}
		}
	} else {
		// Handle generic CSV processing
		lines := strings.Split(content, "\n")
		if len(lines) <= feedConfig.SkipLines {
			return nil, fmt.Errorf("not enough lines in CSV after skipping %d lines", feedConfig.SkipLines)
		}

		// Extract headers
		headers := parseCSVLine(lines[feedConfig.SkipLines])
		for i := range headers {
			headers[i] = strings.TrimSpace(headers[i])
		}

		// Process content lines
		for i := feedConfig.SkipLines + 1; i < len(lines); i++ {
			line := lines[i]
			if line == "" {
				continue
			}

			parts := parseCSVLine(line)
			if len(parts) == 0 {
				continue
			}

			// Create record
			record := make(map[string]interface{})
			for j, part := range parts {
				if j < len(headers) && headers[j] != "" {
					record[headers[j]] = part
				}
			}

			// Add standard metadata
			record["_ingestion_timestamp"] = timestamp
			record["_ingestion_id"] = ingestionID
			record["_source"] = feedName
			record["_feed_type"] = feedConfig.Description

			records = append(records, record)
		}
	}

	log.Printf("Extracted %d records from %s CSV feed", len(records), feedName)
	return records, nil
}

// parseCSVLine parses a CSV line handling quoted values
func parseCSVLine(line string) []string {
	// Simple CSV parsing for demonstration purposes
	// In a real implementation, you might want to use a CSV library

	var result []string
	inQuote := false
	current := ""

	for _, char := range line {
		switch char {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				result = append(result, strings.TrimSpace(current))
				current = ""
			} else {
				current += string(char)
			}
		default:
			current += string(char)
		}
	}

	if current != "" {
		result = append(result, strings.TrimSpace(current))
	}

	// Remove quotes from values
	for i, val := range result {
		result[i] = strings.Trim(val, "\"")
	}

	return result
}

// insertIntoBigQuery inserts records into BigQuery
func insertIntoBigQuery(tableID string, records []map[string]interface{}) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}

	ctx := context.Background()

	// Create BigQuery client
	client, err := bigquery.NewClient(ctx, ProjectID, option.WithScopes(bigquery.Scope))
	if err != nil {
		return 0, fmt.Errorf("failed to create bigquery client: %v", err)
	}
	defer client.Close()

	// Get table reference
	table := client.Dataset(DatasetID).Table(tableID)

	// Check if table exists, create if it doesn't
	if _, err := table.Metadata(ctx); err != nil {
		schema, err := inferSchemaFromRecords(records)
		if err != nil {
			return 0, fmt.Errorf("failed to infer schema: %v", err)
		}

		if err := createTable(ctx, client, DatasetID, tableID, schema); err != nil {
			return 0, fmt.Errorf("failed to create table: %v", err)
		}
	}

	// Insert in batches
	batchSize := 50
	totalInserted := 0

	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}

		batch := records[i:end]
		inserter := table.Inserter()
		if err := inserter.Put(ctx, batch); err != nil {
			log.Printf("Error inserting batch: %v", err)
			continue
		}

		totalInserted += len(batch)
	}

	log.Printf("Inserted %d records into %s", totalInserted, tableID)
	return totalInserted, nil
}

// inferSchemaFromRecords infers a BigQuery schema from sample records
func inferSchemaFromRecords(records []map[string]interface{}) (schema bigquery.Schema, err error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records to infer schema from")
	}

	// Collect all field names
	fieldNames := make(map[string]bool)
	for _, record := range records {
		for key := range record {
			fieldNames[key] = true
		}
	}

	// Create schema fields
	for name := range fieldNames {
		var fieldType bigquery.FieldType

		// Look for the field in records to determine type
		for _, record := range records {
			if value, exists := record[name]; exists && value != nil {
				switch v := value.(type) {
				case int, int32, int64:
					fieldType = bigquery.IntegerFieldType
				case float32, float64:
					fieldType = bigquery.FloatFieldType
				case bool:
					fieldType = bigquery.BooleanFieldType
				case time.Time:
					fieldType = bigquery.TimestampFieldType
				default:
					// Set default field type based on standard fields
					if name == "_ingestion_timestamp" {
						fieldType = bigquery.TimestampFieldType
					} else {
						fieldType = bigquery.StringFieldType
					}
				}
				break
			}
		}

		// Default to string if type not determined
		if fieldType == "" {
			fieldType = bigquery.StringFieldType
		}

		schema = append(schema, &bigquery.FieldSchema{
			Name: name,
			Type: fieldType,
		})
	}

	return schema, nil
}

// createTable creates a new BigQuery table
func createTable(ctx context.Context, client *bigquery.Client, datasetID, tableID string, schema bigquery.Schema) error {
	// Create standard fields if they don't exist
	hasIngestionTimestamp := false
	hasIngestionID := false
	hasSource := false
	hasFeedType := false

	for _, field := range schema {
		switch field.Name {
		case "_ingestion_timestamp":
			hasIngestionTimestamp = true
		case "_ingestion_id":
			hasIngestionID = true
		case "_source":
			hasSource = true
		case "_feed_type":
			hasFeedType = true
		}
	}

	if !hasIngestionTimestamp {
		schema = append(schema, &bigquery.FieldSchema{
			Name: "_ingestion_timestamp",
			Type: bigquery.TimestampFieldType,
		})
	}

	if !hasIngestionID {
		schema = append(schema, &bigquery.FieldSchema{
			Name: "_ingestion_id",
			Type: bigquery.StringFieldType,
		})
	}

	if !hasSource {
		schema = append(schema, &bigquery.FieldSchema{
			Name: "_source",
			Type: bigquery.StringFieldType,
		})
	}

	if !hasFeedType {
		schema = append(schema, &bigquery.FieldSchema{
			Name: "_feed_type",
			Type: bigquery.StringFieldType,
		})
	}

	// Create table
	table := client.Dataset(datasetID).Table(tableID)
	if err := table.Create(ctx, &bigquery.TableMetadata{
		Schema: schema,
	}); err != nil {
		return fmt.Errorf("failed to create table %s.%s: %v", datasetID, tableID, err)
	}

	log.Printf("Created table %s.%s", datasetID, tableID)
	return nil
}

// extractIOCs extracts indicators of compromise from records
func extractIOCs(records []map[string]interface{}, feedName string) ([]ThreatIOC, error) {
	var iocs []ThreatIOC
	timeNow := time.Now().Format(time.RFC3339)

	// Process based on feed type
	switch feedName {
	case "threatfox":
		for _, record := range records {
			if iocValue, ok := record["ioc_value"].(string); ok {
				if iocTypeRaw, ok := record["ioc_type"].(string); ok {
					// Map ThreatFox types to standard types
					iocType := iocTypeRaw
					if strings.Contains(iocTypeRaw, ":") {
						iocType = strings.Split(iocTypeRaw, ":")[0]
					}

					// Map to standard types
					switch iocType {
					case "ip", "ip:port":
						iocType = "ip"
					case "domain", "hostname":
						iocType = "domain"
					case "url":
						iocType = "url"
					case "md5_hash":
						iocType = "md5"
					case "sha1_hash":
						iocType = "sha1"
					case "sha256_hash":
						iocType = "sha256"
					}

					// Create IOC
					ioc := ThreatIOC{
						Type:       iocType,
						Value:      iocValue,
						Source:     feedName,
						Confidence: 60,
						FirstSeen:  timeNow,
						Metadata:   make(map[string]interface{}),
					}

					// Add additional context
					if threatType, ok := record["threat_type"].(string); ok {
						ioc.Metadata["threat_type"] = threatType
					}
					if malware, ok := record["malware"].(string); ok {
						ioc.Metadata["malware"] = malware
					}
					if confidence, ok := record["confidence_level"].(float64); ok {
						ioc.Confidence = int(confidence)
					}
					if firstSeen, ok := record["first_seen_utc"].(string); ok {
						ioc.FirstSeen = firstSeen
					}

					iocs = append(iocs, ioc)
				}
			}
		}

	case "phishtank":
		for _, record := range records {
			if url, ok := record["url"].(string); ok {
				ioc := ThreatIOC{
					Type:       "url",
					Value:      url,
					Source:     feedName,
					Confidence: 70, // PhishTank URLs are verified
					FirstSeen:  timeNow,
					Metadata:   make(map[string]interface{}),
				}

				if target, ok := record["target"].(string); ok {
					ioc.Metadata["target"] = target
				}
				if id, ok := record["phish_id"].(string); ok {
					ioc.Metadata["phish_id"] = id
				}

				iocs = append(iocs, ioc)
			}
		}

	case "urlhaus":
		for _, record := range records {
			if url, ok := record["url"].(string); ok {
				ioc := ThreatIOC{
					Type:       "url",
					Value:      url,
					Source:     feedName,
					Confidence: 70,
					FirstSeen:  timeNow,
					Metadata:   make(map[string]interface{}),
				}

				if threat, ok := record["threat"].(string); ok {
					ioc.Metadata["threat"] = threat
				}
				if tags, ok := record["tags"].(string); ok {
					ioc.Metadata["tags"] = tags
				}
				if dateadded, ok := record["dateadded"].(string); ok {
					ioc.FirstSeen = dateadded
				}

				iocs = append(iocs, ioc)
			}
		}
		
	case "feodotracker":
		for _, record := range records {
			if ip, ok := record["ip_address"].(string); ok {
				ioc := ThreatIOC{
					Type:       "ip",
					Value:      ip,
					Source:     feedName,
					Confidence: 75,
					FirstSeen:  timeNow,
					Metadata:   make(map[string]interface{}),
				}

				if malware, ok := record["malware"].(string); ok {
					ioc.Metadata["malware"] = malware
				}
				
				// Handle additional fields available in Feodo
				for key, value := range record {
					if key != "ip_address" && key != "malware" && !strings.HasPrefix(key, "_") {
						strValue, ok := value.(string)
						if ok && strValue != "" {
							ioc.Metadata[key] = strValue
						}
					}
				}

				iocs = append(iocs, ioc)
			}
		}

	default:
		// Generic IOC extraction from all records
		for _, record := range records {
			// Convert record to JSON for regex scanning
			jsonBytes, err := json.Marshal(record)
			if err != nil {
				continue
			}
			content := string(jsonBytes)

			// Extract using regex patterns
			for iocType, pattern := range IOCPatterns {
				matches := pattern.FindAllString(content, -1)
				for _, match := range matches {
					// Skip standard metadata fields
					if match == "_ingestion_timestamp" || match == "_ingestion_id" || match == "_source" || match == "_feed_type" {
						continue
					}

					ioc := ThreatIOC{
						Type:       iocType,
						Value:      match,
						Source:     feedName,
						Confidence: 50,
						FirstSeen:  timeNow,
						Metadata:   make(map[string]interface{}),
					}

					iocs = append(iocs, ioc)
				}
			}
		}
	}

	// Remove duplicates
	uniqueIOCs := make(map[string]ThreatIOC)
	for _, ioc := range iocs {
		key := fmt.Sprintf("%s:%s", ioc.Type, ioc.Value)
		// Keep the one with higher confidence if duplicate
		if existing, found := uniqueIOCs[key]; found {
			if ioc.Confidence > existing.Confidence {
				uniqueIOCs[key] = ioc
			}
		} else {
			uniqueIOCs[key] = ioc
		}
	}

	// Convert back to slice
	var result []ThreatIOC
	for _, ioc := range uniqueIOCs {
		result = append(result, ioc)
	}

	log.Printf("Extracted %d unique IOCs from %s", len(result), feedName)
	return result, nil
}

// createAnalysisEntry creates an entry in the threat_analysis table
func createAnalysisEntry(feedName string, records []map[string]interface{}, iocs []ThreatIOC, ingestionID string) (string, error) {
	ctx := context.Background()

	// Prepare threat_analysis record
	analysisRecord := map[string]interface{}{
		"source_id":          ingestionID,
		"source_type":        feedName,
		"iocs":               marshallToJSON(iocs),
		"analysis_timestamp": time.Now(),
		"severity":           "medium",
		"confidence":         "medium",
		"vertex_analysis":    marshallToJSON(map[string]interface{}{
			"summary":     fmt.Sprintf("Ingestion of %d records from %s", len(records), feedName),
			"threat_actor": "Unknown",
			"targets":     "Unknown",
			"techniques":  "Unknown",
			"malware":     "Unknown",
			"severity":    "medium",
			"confidence":  "medium",
		}),
	}

	// Create BigQuery client
	client, err := bigquery.NewClient(ctx, ProjectID, option.WithScopes(bigquery.Scope))
	if err != nil {
		return "", fmt.Errorf("failed to create bigquery client: %v", err)
	}
	defer client.Close()

	// Get table reference
	table := client.Dataset(DatasetID).Table("threat_analysis")

	// Check if table exists, create if it doesn't
	if _, err := table.Metadata(ctx); err != nil {
		// Create schema for threat_analysis
		schema := bigquery.Schema{
			{Name: "source_id", Type: bigquery.StringFieldType},
			{Name: "source_type", Type: bigquery.StringFieldType},
			{Name: "iocs", Type: bigquery.StringFieldType},
			{Name: "vertex_analysis", Type: bigquery.StringFieldType},
			{Name: "analysis_timestamp", Type: bigquery.TimestampFieldType},
			{Name: "severity", Type: bigquery.StringFieldType},
			{Name: "confidence", Type: bigquery.StringFieldType},
		}

		if err := createTable(ctx, client, DatasetID, "threat_analysis", schema); err != nil {
			return "", fmt.Errorf("failed to create threat_analysis table: %v", err)
		}
	}

	// Insert record
	inserter := table.Inserter()
	if err := inserter.Put(ctx, []map[string]interface{}{analysisRecord}); err != nil {
		return "", fmt.Errorf("failed to insert analysis record: %v", err)
	}

	log.Printf("Created analysis entry for %s with %d IOCs", feedName, len(iocs))
	return marshallToJSON(analysisRecord), nil
}

// marshallToJSON converts a value to JSON string
func marshallToJSON(v interface{}) string {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		log.Printf("Error marshalling to JSON: %v", err)
		return "{}"
	}
	return string(jsonBytes)
}

// analyzeCSVFile analyzes uploaded CSV file
func analyzeCSVFile(csvContent string, feedName string) (map[string]interface{}, error) {
	if csvContent == "" {
		return map[string]interface{}{"error": "Empty CSV data"}, nil
	}

	// Generate unique ingestion ID
	ingestionID := fmt.Sprintf("upload_%s_%s", feedName, time.Now().Format("20060102150405"))

	// Process CSV
	lines := strings.Split(csvContent, "\n")
	if len(lines) < 2 {
		return map[string]interface{}{"error": "CSV has insufficient data"}, nil
	}

	// Extract headers
	headers := parseCSVLine(lines[0])
	for i := range headers {
		headers[i] = strings.TrimSpace(headers[i])
	}

	// Process records
	var records []map[string]interface{}
	timestamp := time.Now().Format(time.RFC3339)

	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}

		parts := parseCSVLine(line)
		if len(parts) == 0 {
			continue
		}

		// Create record
		record := make(map[string]interface{})
		for j, part := range parts {
			if j < len(headers) && headers[j] != "" {
				record[headers[j]] = part
			}
		}

		// Add standard metadata
		record["_ingestion_timestamp"] = timestamp
		record["_ingestion_id"] = ingestionID
		record["_source"] = "csv_upload"
		record["_feed_type"] = fmt.Sprintf("Uploaded CSV: %s", feedName)

		records = append(records, record)
	}

	if len(records) == 0 {
		return map[string]interface{}{"error": "No valid records found in CSV"}, nil
	}

	// Define custom table name for uploaded data
	tableID := fmt.Sprintf("upload_%s", strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(feedName, " ", "_"), "-", "_")))

	// Insert records
	insertedCount, err := insertIntoBigQuery(tableID, records)
	if err != nil {
		return map[string]interface{}{"error": fmt.Sprintf("Failed to insert records: %v", err)}, err
	}

	// Extract IOCs
	iocs, err := extractIOCs(records, "csv_upload")
	if err != nil {
		log.Printf("Warning: Error extracting IOCs: %v", err)
	}

	// Create analysis entry
	var analysisData string
	if len(iocs) > 0 {
		analysisData, err = createAnalysisEntry("csv_upload", records, iocs, ingestionID)
		if err != nil {
			log.Printf("Warning: Error creating analysis entry: %v", err)
		}
	}

	// Prepare result
	result := map[string]interface{}{
		"status":       "success",
		"feed_name":    feedName,
		"table":        tableID,
		"record_count": insertedCount,
		"ioc_count":    len(iocs),
		"analysis_id":  ingestionID,
		"timestamp":    time.Now().Format(time.RFC3339),
	}

	// Include sample IOCs (limited to 10)
	if len(iocs) > 0 {
		sampleCount := 10
		if len(iocs) < sampleCount {
			sampleCount = len(iocs)
		}
		result["iocs"] = iocs[:sampleCount]
	}

	if analysisData != "" {
		result["analysis"] = analysisData
	}

	return result, nil
}

// Health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"version":     "1.0.0",
		"environment": Environment,
		"project_id":  ProjectID,
		"region":      Region,
		"timestamp":   time.Now().Format(time.RFC3339),
	})
}

func main() {
	// Initialize the ingestion module
	Initialize()

	// Set up HTTP server
	http.HandleFunc("/ingest_threat_data", HTTPHandler)
	http.HandleFunc("/health", healthHandler)
	
	// Get port from environment or use default
	port := getEnv("GO_INGESTION_PORT", "8081")
	
	log.Printf("Starting Go Threat Ingestion server on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
