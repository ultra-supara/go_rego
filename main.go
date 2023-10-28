package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/yaml.v3"
)

func LoadYAMLFiles(dir string) ([]map[string]interface{}, error) {
	var files []map[string]interface{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
			file, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var data map[string]interface{}
			if err := yaml.Unmarshal(file, &data); err != nil {
				return err
			}

			files = append(files, data)
		}
		return nil
	})

	return files, err
}

func main() {
	files, err := LoadYAMLFiles(".github/workflows")
	if err != nil {
		fmt.Println("Error reading policy files:", err)
		return
	}
	ctx := context.Background()

	policy, err := os.ReadFile("policy.rego")
	if err != nil {
		fmt.Println("Error reading policy file:", err)
		return
	}

	r := rego.New(
		rego.Query("data.main.deny"),
		rego.Module("policy.rego",string(policy)),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		fmt.Println("Error preparing query for evaluation:", err)
		return
	}

	seenMessages := make(map[string]bool)

	for _, file := range files {
		results, err := query.Eval(ctx, rego.EvalInput(file))
		if err != nil {
			fmt.Println("Error evaluating query:", err)
			return
		}

		if len(results) > 0 {
			expressions := results[0].Expressions
			for _, expression := range expressions {
				if msgs, ok := expression.Value.([]interface{}); ok {
					for _, msg := range msgs {
						if msgStr, ok := msg.(string); ok && !seenMessages[msgStr] {
							fmt.Println(msgStr)
							seenMessages[msgStr] = true
						}
					}
				}
			}
		}
	}
}
