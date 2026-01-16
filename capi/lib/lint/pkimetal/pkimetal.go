/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package pkimetal

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type PKIMetal struct {
	Info     []string
	Notice   []string
	Warning  []string
	Error    []string
	Bug      []string
	Fatal    []string
	CmdError *string
}

type lintResult struct {
	Linter   string
	Finding  string
	Field    string `json:"Field,omitempty"`
	Code     string `json:"Code,omitempty"`
	Severity string
}

const pkimetalURL = "https://dev.pkimet.al"

var httpClient *http.Client

func init() {
	httpClient = &http.Client{
		Timeout: time.Second * 20,
	}
}

func LintChain(certificates []*x509.Certificate) ([]PKIMetal, error) {
	results := make([]PKIMetal, len(certificates))
	for i, cert := range certificates {
		results[i] = Lint(cert)
	}
	return results, nil
}

func Lint(certificate *x509.Certificate) PKIMetal {
	var err error
	var req *http.Request
	var resp *http.Response

	// Create an HTTP request object.
	if req, err = http.NewRequest(http.MethodPost, pkimetalURL+"/lintcert", strings.NewReader("severity=info&format=json&b64cert="+url.QueryEscape(base64.StdEncoding.EncodeToString(certificate.Raw)))); err != nil {
		return cmdError(fmt.Sprintf("http.NewRequest() => %v", err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "CCADB-Tools capi")

	// Send the HTTP request to the pkimetal server.
	if resp, err = httpClient.Do(req); err != nil {
		return cmdError(fmt.Sprintf("Could not connect to pkimetal (%v)", err))
	} else if resp == nil {
		return cmdError("Empty response from pkimetal")
	}
	defer resp.Body.Close()

	// Check that we received an HTTP 200.
	if resp.StatusCode != http.StatusOK {
		return cmdError(fmt.Sprintf("HTTP %d response from pkimetal", resp.StatusCode))
	}

	// Read the HTTP response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return cmdError(fmt.Sprintf("Could not read response from pkimetal (%v)", err))
	}

	// Parse the JSON-formatted pkimetal output.
	var lintResults []lintResult
	if err = json.Unmarshal(body, &lintResults); err != nil {
		return cmdError(fmt.Sprintf("Could not parse response from pkimetal (%v)", err))
	}

	return parseOutput(lintResults)
}

func NewPKIMetal() PKIMetal {
	return PKIMetal{
		Info:     make([]string, 0),
		Notice:   make([]string, 0),
		Warning:  make([]string, 0),
		Error:    make([]string, 0),
		Bug:      make([]string, 0),
		Fatal:    make([]string, 0),
		CmdError: nil,
	}
}

func cmdError(message string) PKIMetal {
	results := NewPKIMetal()
	results.CmdError = &message
	return results
}

func parseOutput(lintResults []lintResult) PKIMetal {
	result := NewPKIMetal()

	for _, res := range lintResults {
		message := "[" + res.Linter + "]"
		hasCodeOrFinding := false
		if res.Code != "" {
			message += " " + res.Code
			hasCodeOrFinding = true
		}
		if res.Field != "" {
			message += " (" + res.Field + ")"
			hasCodeOrFinding = true
		}
		if hasCodeOrFinding {
			message += " -"
		}
		message += " " + res.Finding

		switch res.Severity {
		case "info":
			result.Info = append(result.Info, message)
		case "notice":
			result.Notice = append(result.Notice, message)
		case "warning":
			result.Warning = append(result.Warning, message)
		case "error":
			result.Error = append(result.Error, message)
		case "bug":
			result.Bug = append(result.Bug, message)
		case "fatal":
			result.Fatal = append(result.Fatal, message)
		default:
			result.Fatal = append(result.Fatal, fmt.Sprintf("unknown severity level from pkimetal (%s)", res.Severity))
		}
	}

	return result
}
