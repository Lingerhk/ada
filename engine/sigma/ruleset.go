package sigma

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
)

// Config is used as argument to creating a new ruleset
type Config struct {
	MemDirectory *embed.FS // load the rules into embed.FS
	// root directory for recursive rule search
	// rules must be readable files with "yml" suffix
	Directory []string
	// by default, a rule parse fail will simply increment Ruleset.Failed counter when failing to
	// parse yaml or rule AST
	// this parameter will cause an early error return instead
	FailOnRuleParse, FailOnYamlParse bool
	// by default, we will collapse whitespace for both rules and data of non-regex rules and non-regex compared data
	// setthig this to true turns that behavior off
	NoCollapseWS bool

	// 从flow_rule的match_by中提取的对应sigma规则的字段(`fields`)，用于flow匹配时按match_by获取个sigma具体的字段值
	ExtractFields map[string][]string
}

func (c Config) validate() error {
	// 优先读取本地目录
	if len(c.Directory) > 0 {
		for _, dir := range c.Directory {
			info, err := os.Stat(dir)
			if os.IsNotExist(err) {
				return fmt.Errorf("%s does not exist", dir)
			}
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", dir)
			}
		}
		return nil
	}

	haveYml := false
	err := fs.WalkDir(c.MemDirectory, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yml") {
			haveYml = true
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk embeded directory err: %v", err)
	}
	if !haveYml {
		return fmt.Errorf("no yaml file found in embeded directory")
	}

	return nil
}

// Ruleset is a collection of rules
type Ruleset struct {
	mu *sync.RWMutex

	Rules []*Tree
	root  []string

	FieldsMap map[string][]string // sigma_id -> fields

	Total, Ok, Failed, Unsupported int
}

// NewRuleset instanciates a Ruleset object
func NewRuleset(c Config, tags []string) (*Ruleset, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}

	files, err := NewRuleFileList(c.MemDirectory, c.Directory)
	if err != nil {
		return nil, err
	}

	var fail int
	rules, err := NewRuleList(c.MemDirectory, files, !c.FailOnYamlParse, c.NoCollapseWS, tags, c.ExtractFields)
	if err != nil {
		switch e := err.(type) {
		case ErrBulkParseYaml:
			fail += len(e.Errs)
		default:
			return nil, err
		}
	}
	result := RulesetFromRuleList(rules)
	result.root = c.Directory
	result.Failed += fail
	result.Total += fail
	return result, nil
}

func RulesetFromRuleList(rules []RuleHandle) *Ruleset {
	fieldsMap := make(map[string][]string)

	var fail, unsupp int
	set := make([]*Tree, 0)
loop:
	for _, raw := range rules {
		if raw.Multipart {
			unsupp++
			continue loop
		}
		tree, err := NewTree(raw)
		if err != nil {
			switch err.(type) {
			case ErrUnsupportedToken, *ErrUnsupportedToken:
				unsupp++
			default:
				fail++
			}
			continue loop
		}
		set = append(set, tree)

		fieldsMap[raw.ID] = raw.Rule.Fields
	}
	return &Ruleset{
		mu:          &sync.RWMutex{},
		Rules:       set,
		FieldsMap:   fieldsMap,
		Failed:      fail,
		Ok:          len(set),
		Unsupported: unsupp,
		Total:       len(rules),
	}
}

func (r *Ruleset) EvalAll(e Event) (Results, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	results := make(Results, 0)
	for _, rule := range r.Rules {
		if res, match := rule.Eval(e); match {
			results = append(results, *res)
		}
	}
	if len(results) > 0 {
		return results, true
	}
	return nil, false
}

// GetRule return thr rule object by rule id
func (r *Ruleset) GetRule(ID string) *Rule {
	for _, rule := range r.Rules {
		if rule.Rule.ID == ID {
			return &rule.Rule.Rule
		}
	}

	return nil
}
