package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/yaml.v3"
)

func LoadYAMLFiles(dir string) ([]map[string]interface{}, error) {
	var files []map[string]interface{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml" {
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
		fmt.Println(err)
		return
	}

	ctx := context.Background()

	r := rego.New(
		rego.Query("data.main.deny"),
		rego.Module("policy.rego", `
		package main

		deny{
			not uses_checkout_v2
		}

		uses_checkout_v2 {
			step := input.jobs.build.steps[_]
			step.uses == "actions/checkout@v2"
		}`),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, file := range files {
		results, err := query.Eval(ctx, rego.EvalInput(file))
		if err != nil {
			fmt.Println(err)
			return
		}

		// Print evaluation results for debugging
		fmt.Println("Evaluation results:", results)

		if len(results) > 0 {
			expressions := results[0].Expressions
			if len(expressions) > 0 {
				if exprValue, ok := expressions[0].Value.(bool); ok && exprValue {
					fmt.Println("Workflow does not use actions/checkout@v2, exiting with error")
				}
			}
		}
	}
}
