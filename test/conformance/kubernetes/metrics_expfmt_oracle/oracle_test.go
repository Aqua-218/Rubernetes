// Differential oracle for Rubernetes' Prometheus exposition: each scraped
// /metrics body is parsed by the expfmt text parser client_golang and the
// Kubernetes e2e MetricsGrabber use (github.com/prometheus/common, vendored in
// Kubernetes v1.36.2), compiled into k8s.io/component-base/metrics/testutil
// through a go test overlay:
//
//	go test -overlay overlay.json k8s.io/component-base/metrics/testutil \
//	  -run TestRubernetesExpfmtOracle -count=1
//
// Input: [{"component": ..., "body": ...}].  Output, per input: the parse
// error (if any), and for each family its name, type, help, the label names
// of every series (le/quantile excluded), and the histogram bucket bounds as
// Go formats them; plus the promlint problems component-base reports.
package testutil

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"testing"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type expfmtInput struct {
	Component string `json:"component"`
	Body      string `json:"body"`
}

type expfmtFamily struct {
	Name    string     `json:"name"`
	Type    string     `json:"type"`
	Help    string     `json:"help"`
	Labels  [][]string `json:"labels"`
	Buckets []string   `json:"buckets,omitempty"`
	Series  int        `json:"series"`
}

type expfmtOutput struct {
	Component string         `json:"component"`
	Error     string         `json:"error,omitempty"`
	Families  []expfmtFamily `json:"families"`
	Lint      []string       `json:"lint"`
}

func TestRubernetesExpfmtOracle(t *testing.T) {
	in := os.Getenv("RUBERNETES_ORACLE_IN")
	out := os.Getenv("RUBERNETES_ORACLE_OUT")
	if in == "" || out == "" {
		t.Skip("RUBERNETES_ORACLE_IN/OUT not set")
	}
	data, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var inputs []expfmtInput
	if err := json.Unmarshal(data, &inputs); err != nil {
		t.Fatal(err)
	}
	results := make([]expfmtOutput, 0, len(inputs))
	for _, input := range inputs {
		result := expfmtOutput{Component: input.Component, Families: []expfmtFamily{}, Lint: []string{}}
		parser := expfmt.NewTextParser(model.LegacyValidation)
		families, err := parser.TextToMetricFamilies(bytes.NewBufferString(input.Body))
		if err != nil {
			result.Error = err.Error()
		}
		names := make([]string, 0, len(families))
		for name := range families {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			mf := families[name]
			family := expfmtFamily{Name: name, Type: mf.GetType().String(), Help: mf.GetHelp(), Labels: [][]string{}, Series: len(mf.GetMetric())}
			seen := map[string]bool{}
			for _, metric := range mf.GetMetric() {
				labels := []string{}
				for _, pair := range metric.GetLabel() {
					labels = append(labels, pair.GetName())
				}
				sort.Strings(labels)
				key, _ := json.Marshal(labels)
				if !seen[string(key)] {
					seen[string(key)] = true
					family.Labels = append(family.Labels, labels)
				}
				if h := metric.GetHistogram(); h != nil && family.Buckets == nil {
					family.Buckets = []string{}
					for _, bucket := range h.GetBucket() {
						family.Buckets = append(family.Buckets, strconv.FormatFloat(bucket.GetUpperBound(), 'g', -1, 64))
					}
				}
			}
			result.Families = append(result.Families, family)
		}
		if result.Error == "" {
			problems, err := NewPromLinter(bytes.NewBufferString(input.Body)).Lint()
			if err != nil {
				result.Lint = append(result.Lint, "lint error: "+err.Error())
			}
			for _, problem := range problems {
				result.Lint = append(result.Lint, problem.String())
			}
		}
		results = append(results, result)
	}
	encoded, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
