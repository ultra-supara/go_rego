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

// LoadYAMLFiles は指定されたディレクトリ内のYAMLファイルを読み込みます。
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

// ProcessResults はrego.ResultSetを処理し、重複しないメッセージを出力します。
func ProcessResults(results rego.ResultSet, seenMessages map[string]bool) {
    if len(results) == 0 {
        return
    }

    for _, result := range results {
        for _, expression := range result.Expressions {
            msgs, ok := expression.Value.([]interface{})
            if !ok {
                continue
            }

            for _, msg := range msgs {
                msgStr, ok := msg.(string)
                if !ok {
                    continue
                }

                if _, seen := seenMessages[msgStr]; !seen {
                    fmt.Println(msgStr)
                    seenMessages[msgStr] = true
                }
            }
        }
    }
}


func main() {
	files, err := LoadYAMLFiles(".github/workflows")
	if err != nil {
		fmt.Println("Error reading policy files:", err)
		return
	}

	policy, err := os.ReadFile("policy.rego")
	if err != nil {
		fmt.Println("Error reading policy file:", err)
		return
	}

	r := rego.New(
		rego.Query("data.main.deny"),
		rego.Module("policy.rego", string(policy)),
	)

	query, err := r.PrepareForEval(context.Background())
	if err != nil {
		fmt.Println("Error preparing query for evaluation:", err)
		return
	}

	seenMessages := make(map[string]bool)

	for _, file := range files {
		results, err := query.Eval(context.Background(), rego.EvalInput(file))
		if err != nil {
			fmt.Println("Error evaluating query:", err)
			return
		}
		ProcessResults(results, seenMessages)
	}
}
