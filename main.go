package smb

import (
	"context"
	"encoding/json"
	"fmt"
)

type Schema struct {
	Target         string `json:"target"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Domain         string `json:"domain"`
	Share          string `json:"share"`
	File           string `json:"file"`
	Exists         bool   `json:"exists"`
	ExactMatch     bool   `json:"match"`
	SubstringMatch bool   `json:"substring_match"`
	RegexMatch     bool   `json:"regex_match"`
	SHA256         bool   `json:"sha256"`
	MD5            bool   `json:"md5"`
	SHA1           bool   `json:"sha1"`
	ExpectedOutput string `json:"expected_output"`
}

func ValidateConfig(config *Schema) error {
	if config.Target == "" {
		return fmt.Errorf("target must be provided")
	}

	if config.Port == 0 {
		return fmt.Errorf("port must be provided")
	}

	comparisonType := []string{}
	if config.Exists {
		comparisonType = append(comparisonType, "exists")
	}

	if config.SubstringMatch {
		comparisonType = append(comparisonType, "substringMatch")
	}

	if config.RegexMatch {
		comparisonType = append(comparisonType, "regexMatch")
	}

	if config.ExactMatch {
		comparisonType = append(comparisonType, "exactMatch")
	}

	if config.SHA256 {
		comparisonType = append(comparisonType, "sha256")
	}

	if config.MD5 {
		comparisonType = append(comparisonType, "md5")
	}

	if config.SHA1 {
		comparisonType = append(comparisonType, "sha1")
	}

	if len(comparisonType) == 0 {
		return fmt.Errorf("exactly one comparison type must be provided; provided none")
	}

	if len(comparisonType) > 1 {
		return fmt.Errorf("exactly one comparison type must be provided; provided multiple: %v", comparisonType)
	}

	if config.ExpectedOutput == "" && !config.Exists {
		return fmt.Errorf("expectedOutput must be provided for all comparison types except exists")
	}

	return nil
}

func Run(ctx context.Context, config string) error {
	schema := Schema{}

	err := json.Unmarshal([]byte(config), &schema)
	if err != nil {
		return err
	}

	return nil
}
