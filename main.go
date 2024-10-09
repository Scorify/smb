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
	"slices"
	"strings"

	"github.com/hirochachacha/go-smb2"
	"github.com/scorify/schema"
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

func Validate(config string) error {
	conf := Schema{}

	err := schema.Unmarshal([]byte(config), &conf)
	if err != nil {
		return err
	}

	if conf.Server == "" {
		return fmt.Errorf("server is required; got %q", conf.Server)
	}

	if conf.Port <= 0 || conf.Port > 65535 {
		return fmt.Errorf("port must be valid; got %d", conf.Port)
	}

	if conf.Username == "" {
		return fmt.Errorf("username is required; got %q", conf.Username)
	}

	if conf.Domain == "" {
		return fmt.Errorf("domain is required; got %q", conf.Domain)
	}

	if conf.Share == "" {
		return fmt.Errorf("share is required; got %q", conf.Share)
	}

	if conf.File == "" {
		return fmt.Errorf("file is required; got %q", conf.File)
	}

	if slices.Contains([]string{"exists", "exactMatch", "substringMatch", "regexMatch", "sha256", "md5", "sha1"}, conf.MatchType) {
		return fmt.Errorf("match_type must be one of exists, exactMatch, substringMatch, regexMatch, sha256, md5, sha1; got %q", conf.MatchType)
	}

	if conf.ExpectedOutput == "" && conf.MatchType != "exists" {
		return fmt.Errorf("expected_output is required for non-exist checks; got %q for %q", conf.ExpectedOutput, conf.MatchType)
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
