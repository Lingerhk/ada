package flow

import (
	"ada/engine/common"
	"ada/infra/base"
	utime "ada/infra/time"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	logger "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var eventTypes = []string{common.EventTypeCount, common.EventTypeMultiEve, common.EventTypeMultiPkt, common.EventTypeMultiEvePkt}

// 样例: $s1.SourceProcessId == $s3.ProcessId
type Condition struct {
	fieldOneIdx int64  // 1
	fieldOneVal string // SourceProcessId
	fieldTwoIdx int64  // 3
	fieldTwoVal string // ProcessId
	fieldTwoTyp string // const, str, slice, cache, ldap, default: str
	operation   string // ==, 支持的操作码: ==、!=、>、<、>=、<=、in
}

// yml to struct: https://zhwt.github.io/yaml-to-go/
type FlowRule struct {
	Title       string   `yaml:"title"`
	ID          string   `yaml:"id"`
	Status      string   `yaml:"status"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
	Author      string   `yaml:"author"`
	Date        string   `yaml:"date"`
	Modified    string   `yaml:"modified"`
	Tags        []string `yaml:"tags"`
	Logsource   struct {
		Product string `yaml:"product"`
	} `yaml:"logsource"`
	Detection struct {
		EventType string `yaml:"event_type"`
		WinSize   string `yaml:"win_size"`
		WinSizeTs int64  // win_size的时间戳(int64类型，在初始化时从WinSize转换而来)
		Sorted    bool   `yaml:"sorted"`
		Selection struct {
			SigmaID []string `yaml:"sigma_id"`
			MatchBy string   `yaml:"match_by"`
		} `yaml:"selection"`
		Conditions []Condition
	} `yaml:"detection"`
	Level        string              `yaml:"level"`
	UniqueFilter []string            `yaml:"unique_filter"` // 唯一性过滤（如果之前存在该事件，测忽略）
	ExtFields    map[string][]string // 该字段不是flow yaml文件中的字段，仅用于内存存储. eg: {"sigma_id1":["field1","field2"],"sigma_id2":["field3"]} 这里的key(sigma_id)是全量，val是flow规则文件中的extField
}

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

// NewRuleList 	reads a list of sigma rule paths and parses them to rule objects
func NewRuleList(files []string) ([]FlowRule, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("missing rule file list")
	}

	var err error
	var data []byte
	var r FlowRule
	rules := make([]FlowRule, 0)
	for _, file := range files {
		data, err = os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, &r); err != nil {
			return nil, err
		}

		// ignore which logsrouce is not 'sigma_flow'
		if r.Logsource.Product != "sigma_flow" {
			logger.Warnf("ignore invalid logsource:%s", r.Logsource.Product)
			continue
		}

		// ignore status if 'disabled'
		if r.Status == "disabled" {
			logger.Warnf("ignore status 'disabled' flow:%s", r.ID)
			continue
		}

		// check at least one tag in tags
		if len(r.Tags) == 0 {
			logger.Warnf("empty tags(at least one), will ignore this flow:%s", r.ID)
			continue
		}

		// ignore which event_type is 'multi_eve_pkt'
		validEventType := false
		for _, et := range eventTypes {
			if r.Detection.EventType == et {
				validEventType = true
				break
			}
		}
		if !validEventType {
			logger.Warnf("ignore invalid event_type:%s", r.Detection.EventType)
			continue
		}

		// check level
		validEventLevel := false
		for _, lvl := range []string{"info", "low", "medium", "high", "critical"} {
			if r.Level == lvl {
				validEventLevel = true
				break
			}
		}
		if !validEventLevel {
			logger.Warnf("ignore invalid level:%s", r.Level)
			continue
		}

		// ignore the repeated flow_id rule
		for _, rt := range rules {
			if r.ID == rt.ID {
				logger.Warnf("ignore repeated flow_id:%s", r.ID)
				continue
			}
		}

		// check the length of Detection.SigmaID
		if len(r.Detection.Selection.SigmaID) > common.MaxFlowSelections {
			logger.Warnf("ignore too length(%d) Selection.SigmaID(must <= %d)", len(r.Detection.Selection.SigmaID), common.MaxFlowSelections)
			continue
		}

		// check the win_size of Detection.WinSize
		val, err := utime.ConvertStrTime(r.Detection.WinSize)
		if err != nil || val == 0 || val > common.MaxFlowWinSize {
			logger.Warnf("ignore invalid Detection.WinSize(%s)", r.Detection.WinSize)
			continue
		}
		r.Detection.WinSizeTs = val

		// parse match_by into Conditions object, and update fields into sigma rule 'fields'
		r.Detection.Conditions = parseMatchByExpression(r.Detection.Selection.MatchBy)
		sFields := extractFields(r.Detection.Conditions, r.Detection.Selection.SigmaID)

		sigmaRuleFields := make(map[string][]string)
		for sid, fields := range sFields {
			// remove internal filed: _count and is number
			var fieldList []string
			for _, field := range fields {
				if field == "_count" { // ignore: _count
					continue
				}
				if _, err := strconv.Atoi(field); err == nil { // ignore: is number
					continue
				}

				fieldList = append(fieldList, field)
			}

			if v, ok := sigmaRuleFields[sid]; ok {
				sigmaRuleFields[sid] = append(v, fieldList...)
				sigmaRuleFields[sid] = base.RemoveDuplicate(sigmaRuleFields[sid])
			} else {
				sigmaRuleFields[sid] = base.RemoveDuplicate(fieldList)
			}
		}

		r.ExtFields = sigmaRuleFields
		rules = append(rules, r)
	}

	return rules, nil
}

// redis存储结构
// flow_rule_map(hash)
// | sigma_id1  flow_id1,flow_id2,...
// | sigma_id2  flow_id5,flow_id7,...
// | sigma_id3  flow_id3,flow_id9,...
func (r *Ruleset) LoadRuleCache() error {
	ctx := context.Background()
	// del old cache
	err := r.redisCli.Del(ctx, common.FlowRuleMapKey).Err()
	if err != nil {
		return err
	}

	// read sigma_id list form flow_rule
	sigmaIDMap := make(map[string]any)
	for _, fRule := range r.FlowRules {
		if len(fRule.Detection.Selection.SigmaID) == 0 {
			logger.Warnf("ignore empty sigma_id flow_rule:%s", fRule.ID)
			continue
		}

		for _, sigmaId := range fRule.Detection.Selection.SigmaID {
			if _, ok := sigmaIDMap[sigmaId]; ok {
				sigmaIDMap[sigmaId] = fmt.Sprintf("%s,%s", sigmaIDMap[sigmaId], fRule.ID)
			} else {
				sigmaIDMap[sigmaId] = fRule.ID
			}
		}
	}

	// load into redis
	err = r.redisCli.HMSet(ctx, common.FlowRuleMapKey, sigmaIDMap).Err()
	if err != nil {
		return err
	}

	return nil
}

func extractFields(conditions []Condition, sigmaIDs []string) map[string][]string {
	sigmaFields := make(map[string][]string)
	for _, sid := range sigmaIDs {
		sigmaFields[sid] = []string{}
	}

	sigmaRuleTotal := len(sigmaIDs)
	for _, c := range conditions {
		if c.fieldOneIdx > int64(sigmaRuleTotal-1) {
			logger.Warnf("fieldOneIdx(%d) out of index, sigmaID len:%d", c.fieldOneIdx, sigmaRuleTotal)
			continue
		}

		if c.operation == "in" {
			// 只处理表达式前部分: $s1.LoginType in $v.slice.["ss", "sd", "sc"], 还支持`in $v.cache.key_xxxx`
			sid := sigmaIDs[c.fieldOneIdx]
			sigmaFields[sid] = append(sigmaFields[sid], c.fieldOneVal)
		} else {
			// 表达式前/后两部分: $s1.LoginType == $3.UserLoginType
			if c.fieldTwoIdx > int64(sigmaRuleTotal-1) {
				logger.Warnf("fieldTwoIdx(%d) out of index, sigmaID len:%d", c.fieldTwoIdx, sigmaRuleTotal)
				continue
			}

			sid1 := sigmaIDs[c.fieldOneIdx]
			sigmaFields[sid1] = append(sigmaFields[sid1], c.fieldOneVal)

			sid2 := sigmaIDs[c.fieldTwoIdx]
			sigmaFields[sid2] = append(sigmaFields[sid2], c.fieldTwoVal)
		}
	}

	return sigmaFields
}

func parseMatchByExpression(matchBy string) []Condition {
	var conditions []Condition

	// TODO: 暂时兼容_count表达式: `$s1._count == 3` 后续可继续优化
	// 后续可支持:
	// $s1.LoginType._count == 3 ?????
	if strings.Contains(matchBy, "$s1._count") {
		parts := strings.SplitN(strings.ReplaceAll(matchBy, " ", ""), "==", 2)
		if len(parts) != 2 {
			logger.Warnf("0-invalid condition(%s), will ignore!", matchBy)
			return conditions
		}
		conditions = append(conditions, Condition{fieldOneIdx: 0, fieldOneVal: "_count", fieldTwoIdx: 0, fieldTwoVal: "3", fieldTwoTyp: "const", operation: "=="})
		return conditions
	}

	// matchBy 多条件的，目前仅支持`AND`， 后续实现`OR`和'()'
	// matchBy: `$s1.SubjectUserName == $s2.SubjectUserName AND $s1.SourceProcessId == $s2.ProcessId AND $s1.LoginType in $v.slice.["ss", "sd", "sc"]`
	// 将表达式分割成条件, 解析每个条件
	for _, condition := range strings.Split(matchBy, "AND") {
		conditions = append(conditions, parseCondition(condition))
	}

	return conditions
}

func parseCondition(condition string) Condition {
	var c Condition

	expression := strings.ReplaceAll(condition, " ", "") // 移除所有空格符
	if strings.Contains(expression, "$v.slice.") {
		// 表达式: $s1.LoginType in $v.slice.["ss", "sd", "sc"]
		parts := strings.SplitN(expression, "in$v.slice.", 2)
		if len(parts) != 2 {
			logger.Warnf("1-invalid condition(%s), will ignore!", condition)
			return c
		}

		field1 := parts[0] // `$s1.LoginType`
		field2 := parts[1] // `["ss","sd","sc"]`

		if !strings.HasPrefix(field1, "$s") {
			logger.Warnf("2-invalid condition(%s), will ignore!", condition)
			return c
		}

		oneIdx, oneVal := parseConditionKV(field1)

		// 将字符串解析为 JSON 数组
		var stringList []string
		if err := json.Unmarshal([]byte(field2), &stringList); err != nil {
			logger.Warnf("3-invalid condition(json parse field2: %s err:%v", field2, err)
			return c
		}

		c.fieldOneIdx = oneIdx
		c.fieldOneVal = oneVal
		c.fieldTwoIdx = -1
		c.fieldTwoVal = strings.Join(stringList, ",")
		c.fieldTwoTyp = "slice"
		c.operation = "in"
	} else if strings.Contains(expression, "$v.cache.") {
		// 表达式: $s1.LoginType in $v.cache.key_xxxx
		parts := strings.SplitN(expression, "in$v.cache.", 2)
		if len(parts) != 2 {
			logger.Warnf("1-invalid condition(%s), will ignore!", condition)
			return c
		}

		field1 := parts[0] // `$s1.LoginType`
		field2 := parts[1] // `key_xxxx

		if !strings.HasPrefix(field2, "key_") {
			logger.Warnf("2-invalid condition(%s), will ignore!", condition)
			return c
		}

		if !strings.HasPrefix(field1, "$s") {
			logger.Warnf("3-invalid condition(%s), will ignore!", condition)
			return c
		}

		oneIdx, oneVal := parseConditionKV(field1)

		c.fieldOneIdx = oneIdx
		c.fieldOneVal = oneVal
		c.fieldTwoIdx = -1
		c.fieldTwoVal = field2
		c.fieldTwoTyp = "cache"
		c.operation = "in"
	} else if strings.Contains(expression, "$v.ldap.") {
		// 表达式: $s1.LoginType in $v.ldap.key_xxxx
		// TODO: 后续实现
	} else {
		// 其他表达式: `$s1.SubjectUserName == $s2.SubjectUserName` 或 `$s1.SourceProcessId !=$s2.ProcessId` 或 `$s1.SubjectUserName == admin`
		valid := false
		var opType string
		for _, op := range []string{"==", "!=", ">", "<", ">=", "<="} {
			if strings.Contains(expression, op) {
				valid = true
				opType = op
				break
			}
		}
		if !valid {
			logger.Warn("4-invalid condition has no op, will ignore")
			return c
		}

		// 按照op进行切割，在判断`$s1.SourceProcessId !=$s2.ProcessId` 还是 `$s1.SubjectUserName==admin`
		parts := strings.SplitN(expression, opType, 2)
		if len(parts) != 2 {
			logger.Warnf("5-invalid condition(%s), will ignore!", condition)
			return c
		}

		field1 := parts[0] // `$s1.SubjectUserName`
		field2 := parts[1] // `$s2.ProcessId` 或 `admin`

		if !strings.HasPrefix(field1, "$s") {
			logger.Warnf("6-invalid condition(%s), will ignore!", condition)
			return c
		}

		oneIdx, oneVal := parseConditionKV(field1)

		c.fieldOneIdx = oneIdx
		c.fieldOneVal = oneVal
		c.operation = opType

		if strings.HasPrefix(field2, "$s") {
			// `$s2.ProcessId`
			twoIdx, twoVal := parseConditionKV(field2)
			c.fieldTwoIdx = twoIdx
			c.fieldTwoVal = twoVal
			c.fieldTwoTyp = "str"
		} else {
			// `admin`
			c.fieldTwoIdx = -1
			c.fieldTwoVal = field2
			c.fieldTwoTyp = "const"
		}
	}

	return c
}

// parseCondition: `$s1.ProcessId`, 返回 index和field
func parseConditionKV(condition string) (int64, string) {
	if !strings.HasPrefix(condition, "$s") {
		logger.Warnf("01-invalid condition(%s), will ignore!", condition)
		return -1, ""
	}

	parts := strings.SplitN(condition, ".", 2) // parts[0]: $s1, parts[1]: ProcessId
	if len(parts) != 2 {
		logger.Warnf("02-invalid condition(%s), will ignore!", condition)
		return -1, ""
	}

	i64, err := strconv.ParseInt(strings.TrimPrefix(parts[0], "$s"), 10, 64)
	if err != nil {
		logger.Warnf("03-invalid condition(%s, err:%v), will ignore!", condition, err)
		return -1, ""
	}

	if i64 < 1 || i64 > common.MaxFlowSelections {
		logger.Warnf("04-invalid condition(%s), will ignore!", condition)
		return -1, ""
	}

	return i64 - 1, parts[1]
}
