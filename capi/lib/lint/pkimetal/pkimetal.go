/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package pkimetal

import (
	"crypto/x509"
	"log"
	"strings"
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

func LintChain(certificates []*x509.Certificate) ([]PKIMetal, error) {
	results := make([]PKIMetal, len(certificates))
	for i, cert := range certificates {
		results[i] = Lint(cert)
	}
	return results, nil
}

func Lint(certificate *x509.Certificate) PKIMetal {
	return parseOutput("I: PKIMetal linting not yet implemented")
}

func NewPKIMetal() PKIMetal {
	return PKIMetal{
		Info:    make([]string, 0),
		Notice:  make([]string, 0),
		Warning: make([]string, 0),
		Error:   make([]string, 0),
		Bug:     make([]string, 0),
		Fatal:   make([]string, 0),
	}
}

func parseOutput(output string) PKIMetal {
	result := NewPKIMetal()
	for _, line := range strings.Split(output, "\n") {
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "E: ") {
			result.Error = append(result.Error, line[3:])
		} else if strings.HasPrefix(line, "W: ") {
			result.Warning = append(result.Warning, line[3:])
		} else if strings.HasPrefix(line, "I: ") {
			result.Info = append(result.Info, line[3:])
		} else {
			log.Printf(`unexpected PKIMetal output: "%s"`, line)
		}
	}
	return result
}
