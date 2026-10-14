package fingerprint

import (
	_ "embed"
	"encoding/json"
	"os"
)

//go:embed rules.json
var embeddedRules []byte

// RulesSet is the on-disk format of the rules file.
type RulesSet struct {
	Rules []Rule `json:"rules"`
}

// LoadDefaultRules returns a compiled Engine from the embedded rules. When the
// RULES_FILE environment variable points at an external file, that file is used
// instead, so recognition rules can be updated without recompiling the binary.
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
