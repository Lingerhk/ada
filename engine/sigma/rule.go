package sigma

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	logger "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v3"
)

// RuleHandle is a meta object containing all fields from raw yaml, but is enhanced to also
// hold debugging info from the tool, such as source file path, etc
type RuleHandle struct {
	Rule

	Path         string `json:"path"`
	Multipart    bool   `json:"multipart"`
	NoCollapseWS bool   `json:"noCollapseWS"`
}

// Rule defines raw rule conforming to sigma rule specification
// https://github.com/Neo23x0/sigma/wiki/Specification
// only meant to be used for parsing yaml that matches Sigma rule definition
type Rule struct {
	Author         string   `yaml:"author" json:"author"`
	Description    string   `yaml:"description" json:"description"`
	Falsepositives []string `yaml:"falsepositives" json:"falsepositives"`
	Fields         []string `yaml:"fields" json:"fields"`
	UniqueFields   []string `yaml:"unique_fields" json:"unique_fields"`
	ID             string   `yaml:"id" json:"id"`
	Level          string   `yaml:"level" json:"level"`
	RdxKey         string   `yaml:"rdx_key" json:"rdx_key"`
	Title          string   `yaml:"title" json:"title"`
	Status         string   `yaml:"status" json:"status"`
	References     []string `yaml:"references" json:"references"`

	Logsource `yaml:"logsource" json:"logsource"`
	Detection `yaml:"detection" json:"detection"`
	Tags      `yaml:"tags" json:"tags"`
}

// HasTags returns true if the rule contains all provided tags, otherwise false
func (r *Rule) HasTags(tags []string) bool {
	lookup := make(map[string]bool, len(r.Tags))
	for _, tag := range r.Tags {
		lookup[tag] = true
	}
	for _, tag := range tags {
		if _, ok := lookup[tag]; !ok {
			return false
		}
	}
	return true
}

// margeFields returns the deduplicated results of `extFields` in flow ruleset and sigma rule's `fields`
func (r *Rule) margeFields(extFields map[string][]string) {
	//logger.Debugf("srcFields: %#v, extFields:%#v", r.Fields, extFields)

	var srcFields []string
	if v, ok := extFields[r.ID]; ok {
		srcFields = append(r.Fields, v...)
	} else {
		return
	}

	// 对srcFields去重
	var destFields []string
	for _, sField := range srcFields {
		// 忽略掉类似`_count`之类的内部(非sigma rule中定义)的flow field
		if strings.HasPrefix(sField, "_") {
			continue
		}

		exist := false
		for _, dField := range destFields {
			if sField == dField {
				exist = true
				break
			}
		}

		if !exist {
			destFields = append(destFields, sField)
		}
	}

	//logger.Debugf("destFields: %#v", destFields)

	r.Fields = destFields
}

func (r *Rule) checkLevel() bool {
	// levels defines in engine/common/ruletype.go
	for _, l := range []string{"info", "low", "medium", "high", "critical"} {
		if r.Level == l {
			return true
		}
	}

	return false
}

// RuleFromYAML parses yaml data into Rule object
func RuleFromYAML(data []byte) (r Rule, err error) {
	err = yaml.Unmarshal(data, &r)
	return
}

// IsMultipart checks if rule is multipart
func IsMultipart(data []byte) bool {
	return !bytes.HasPrefix(data, []byte("---")) && bytes.Contains(data, []byte("---"))
}

// NewRuleList 	reads a list of sigma rule paths and parses them to rule objects
func NewRuleList(files []string, skip, noCollapseWS bool, tags []string, extFields map[string][]string) ([]RuleHandle, error) {
	if len(files) == 0 {
		return nil, ErrMissingRuleList
	}

	var err error
	var data []byte
	errs := make([]ErrParseYaml, 0)
	rules := make([]RuleHandle, 0)
loop:
	for i, path := range files {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		r, err := RuleFromYAML(data)
		if err != nil {
			if skip {
				errs = append(errs, ErrParseYaml{
					Path:  path,
					Count: i,
					Err:   err,
				})
				continue loop
			}
			return nil, &ErrParseYaml{Err: err, Path: path}
		}

		// 检查tags，必须至少有一个tag，指定att&ck Id
		if len(r.Tags) == 0 {
			return nil, &ErrParseYaml{Err: fmt.Errorf("empty tags(at least one), sigma_id:%s", r.ID), Path: path}
		}

		if !r.HasTags(tags) {
			continue loop
		}

		// 将extFields中可能存在该sima规则的`fields`更新到该rule的fields字段(去重)
		r.margeFields(extFields)

		// 检测yml规则文件中level是否书写正确
		if !r.checkLevel() {
			logger.Warnf("check level in rule(%s) failed: %s, will ignore!", r.ID, r.Level)
			continue
		}

		rules = append(rules, RuleHandle{
			Path:         path,
			Rule:         r,
			NoCollapseWS: noCollapseWS,
			Multipart:    IsMultipart(data),
		})
	}
	return rules, func() error {
		if len(errs) > 0 {
			return ErrBulkParseYaml{Errs: errs}
		}
		return nil
	}()
}

// Logsource represents the logsource field in sigma rule
// It defines relevant event streams and is used for pre-filtering
type Logsource struct {
	Product    string `yaml:"product" json:"product"`
	Category   string `yaml:"category" json:"category"`
	Service    string `yaml:"service" json:"service"`
	Definition string `yaml:"definition" json:"definition"`
}

// Detection represents the detection field in sigma rule
// contains condition expression and identifier fields for building AST
type Detection map[string]any

func (d Detection) Extract() map[string]any {
	tx := make(map[string]any)
	for k, v := range d {
		if k != "condition" {
			tx[k] = v
		}
	}
	return tx
}

// Tags contains a metadata list for tying positive matches together with other threat intel sources
// For example, for attaching MITRE ATT&CK tactics or techniques to the event
type Tags []string

// Result is an object returned on positive sigma match
type Result struct {
	Tags `json:"tags"`

	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Status      string            `json:"status"`
	Level       string            `json:"level"`
	Fields      map[string]string `json:"fields"`
	UniqueId    string            `json:"unique_id"`
	Timestamp   int64             `json:"timestamp"`
}

// Results should be returned when single event matches multiple rules
type Results []Result

// NewRuleFileList finds all yaml files from defined root directories
// Subtree is scanned recursively
// No file validation, other than suffix matching
func NewRuleFileList(dirs []string) ([]string, error) {
	out := make([]string, 0)

	if len(dirs) == 0 {
		return nil, fmt.Errorf("no rule directories provided")
	}

	for _, dir := range dirs {
		if err := filepath.Walk(dir, func(
			path string,
			info os.FileInfo,
			err error,
		) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, "yml") {
				out = append(out, path)
			}
			return nil
		}); err != nil {
			return out, err
		}
	}

	return out, nil
}
