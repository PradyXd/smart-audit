package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

// DeepSeekRequest represents the structure of the request to DeepSeek API
type DeepSeekRequest struct {
	Model     string    `json:"model"`
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"max_tokens,omitempty"`
}

// Message represents a message in the conversation
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// DeepSeekResponse represents the structure of the response from DeepSeek API
type DeepSeekResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// EnhanceAnalysisWithAI provides AI-powered insights for contract vulnerabilities
func EnhanceAnalysisWithAI(contract string) (string, error) {
	apiKey := os.Getenv("DEEPSEEK_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("DEEPSEEK_API_KEY environment variable not set")
	}

	// Prepare the request payload
	requestPayload := DeepSeekRequest{
		Model: "deepseek-R1", // Adjust this based on the specific DeepSeek model you're using
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are a smart contract security expert. Analyze the following Solidity contract for potential vulnerabilities and provide detailed insights.",
			},
			{
				Role:    "user",
				Content: fmt.Sprintf("Analyze this smart contract for security vulnerabilities:\n%s", contract),
			},
		},
		MaxTokens: 500, // Adjust as needed
	}

	// Convert payload to JSON
	payloadBytes, err := json.Marshal(requestPayload)
	if err != nil {
		return "", fmt.Errorf("error marshaling request: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"https://api.deepseek.com/v1/chat/completions",
		bytes.NewBuffer(payloadBytes),
	)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var deepSeekResp DeepSeekResponse
	err = json.Unmarshal(body, &deepSeekResp)
	if err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	// Extract and return analysis
	if len(deepSeekResp.Choices) > 0 {
		return deepSeekResp.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("no analysis returned from DeepSeek API")
}
