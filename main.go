package smb

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/hirochachacha/go-smb2"
)

type Schema struct {
	Server         string `key:"server"`
	Port           int    `key:"port" default:"445"`
	Username       string `key:"username"`
	Password       string `key:"password"`
	Domain         string `key:"domain"`
	Share          string `key:"share" default:"C$"`
	File           string `key:"file"`
	MatchType      string `key:"match_type" default:"exists" enum:"exists,exactMatch,substringMatch,regexMatch,sha256,md5,sha1"`
	ExpectedOutput string `key:"expected_output"`
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

func clean(input error) error {
	return fmt.Errorf("%s", strings.ReplaceAll(input.Error(), "\x00", ""))
}

func Run(ctx context.Context, config string) error {
	schema := Schema{}

	err := json.Unmarshal([]byte(config), &schema)
	if err != nil {
		return err
	}

	err = ValidateConfig(&schema)
	if err != nil {
		return err
	}

	connStr := fmt.Sprintf("%s:%d", schema.Target, schema.Port)
	conn, err := net.Dial("tcp", connStr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", connStr, clean(err))
	}
	defer conn.Close()

	smbDialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     schema.Username,
			Password: schema.Password,
			Domain:   schema.Domain,
		},
	}

	smbConn, err := smbDialer.DialContext(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", connStr, clean(err))
	}
	defer smbConn.Logoff()

	sharePath := fmt.Sprintf(`\\%s\%s`, schema.Target, schema.Share)
	fs, err := smbConn.Mount(sharePath)
	if err != nil {
		return fmt.Errorf("failed to mount %s: %w", sharePath, clean(err))
	}
	defer fs.Umount()

	file, err := fs.Open(schema.File)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", schema.File, clean(err))
	}
	defer file.Close()

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start of %s: %w", schema.File, clean(err))
	}

	bodyBytes, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", schema.File, clean(err))
	}

	switch {
	case schema.Exists:
		return nil
	case schema.ExactMatch:
		if string(bodyBytes) != schema.ExpectedOutput {
			return fmt.Errorf("response does not match expected output: %q", schema.ExpectedOutput)
		}
	case schema.SubstringMatch:
		if !strings.Contains(string(bodyBytes), schema.ExpectedOutput) {
			return fmt.Errorf("response does not contain expected output: %q", schema.ExpectedOutput)
		}
	case schema.RegexMatch:
		pattern, err := regexp.Compile(schema.ExpectedOutput)
		if err != nil {
			return fmt.Errorf("encountered error compiling regex pattern: %v", err)
		}

		if !pattern.Match(bodyBytes) {
			return fmt.Errorf("response does not match regex pattern: %s", schema.ExpectedOutput)
		}
	case schema.SHA256:
		sha256 := fmt.Sprintf("%x", sha256.Sum256(bodyBytes))
		if sha256 != schema.ExpectedOutput {
			return fmt.Errorf("response does not match expected sha256: %s", schema.ExpectedOutput)
		}
	case schema.MD5:
		md5 := fmt.Sprintf("%x", md5.Sum(bodyBytes))
		if md5 != schema.ExpectedOutput {
			return fmt.Errorf("response does not match expected md5: %s", schema.ExpectedOutput)
		}
	case schema.SHA1:
		sha1 := fmt.Sprintf("%x", sha1.Sum(bodyBytes))
		if sha1 != schema.ExpectedOutput {
			return fmt.Errorf("response does not match expected sha1: %s", schema.ExpectedOutput)
		}
	}

	return nil
}
