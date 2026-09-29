// Differential oracle for kubelet env files (pkg/kubelet/util/env ParseEnv,
// Kubernetes v1.36.2), compiled into the package through a go test overlay:
//
//	go test -overlay overlay.json ./pkg/kubelet/util/env -run TestRubernetesEnvFileOracle -count=1
//
// Each case is a file content and a key; the result is the value or the error.
package env

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type envFileCase struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Key     string `json:"key"`
}

type envFileResult struct {
	Name  string  `json:"name"`
	Value string  `json:"value"`
	Error *string `json:"error,omitempty"`
}

func TestRubernetesEnvFileOracle(t *testing.T) {
	in, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Cases []envFileCase `json:"cases"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	results := []envFileResult{}
	for i, c := range input.Cases {
		path := filepath.Join(dir, "env")
		if err := os.WriteFile(path, []byte(c.Content), 0o644); err != nil {
			t.Fatal(err)
		}
		value, err := ParseEnv(path, c.Key)
		result := envFileResult{Name: c.Name, Value: value}
		if err != nil {
			msg := err.Error()
			result.Error = &msg
		}
		results = append(results, result)
		_ = i
	}
	out, _ := json.Marshal(map[string]interface{}{"results": results})
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
