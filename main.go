package check_template

import (
	"context"
	"encoding/json"
)

type Schema struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
}

func Run(ctx context.Context, config string) error {
	schema := Schema{}

	err := json.Unmarshal([]byte(config), &schema)
	if err != nil {
		return err
	}

	return nil
}
