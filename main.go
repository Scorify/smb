package smb

import (
	"context"
	"encoding/json"
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

func Run(ctx context.Context, config string) error {
	schema := Schema{}

	err := json.Unmarshal([]byte(config), &schema)
	if err != nil {
		return err
	}

	return nil
}
