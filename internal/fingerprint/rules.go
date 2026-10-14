package fingerprint

import (
	_ "embed"
	"encoding/json"
	"os"
)

//go:embed rules.json
// embeddedRules 是编译期打入二进制内的规则文件内容。
var embeddedRules []byte

// RulesSet 是规则文件的磁盘存储格式。
type RulesSet struct {
	Rules []Rule `json:"rules"`
}

// LoadDefaultRules 从内嵌规则文件加载并编译出识别引擎。当 RULES_FILE
// 环境变量指向某个外部文件时,优先使用该文件,从而无需重编译即可更新规则。
func LoadDefaultRules() (*Engine, error) {
	data := embeddedRules
	if p := os.Getenv("RULES_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		data = b
	}
	var set RulesSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	return NewEngine(set.Rules), nil
}
