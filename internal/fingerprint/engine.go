// Package fingerprint implements a rule-driven banner fingerprinting engine.
//
// The engine itself contains no protocol-specific logic: every recognition
// decision is expressed as data in rules.json, which is embedded into the
// binary at build time and may be overridden at runtime via RULES_FILE.
package fingerprint

import (
	"regexp"
	"sort"
)

// Input is a single raw scan record.
type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result is a single identified fingerprint.
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Rule describes one fingerprint signature. All matching/extraction is
// expressed declaratively so that updating recognition behaviour means editing
// JSON, not Go code.
type Rule struct {
	Name         string   `json:"name"`
	Protocol     string   `json:"protocol"`
	Priority     int      `json:"priority"`
	Patterns     []string `json:"patterns"`
	Product      string   `json:"product,omitempty"`
	ProductRegex string   `json:"product_regex,omitempty"`
	Version      string   `json:"version,omitempty"`
	VersionRegex string   `json:"version_regex,omitempty"`
	OSRegex      string   `json:"os_regex,omitempty"`
	Confidence   float64  `json:"confidence"`

	compiledPatterns []*regexp.Regexp
	compiledProduct  *regexp.Regexp
	compiledVersion  *regexp.Regexp
	compiledOS       *regexp.Regexp
}

// Engine identifies banners against an ordered set of rules.
type Engine struct {
	rules []Rule
}

// NewEngine compiles the given rules into an Engine. Rules are ordered by
// descending priority; the first matching rule wins. Invalid regexes are
// skipped rather than causing a startup failure.
func NewEngine(rules []Rule) *Engine {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if !r.compile() {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Priority > out[j].Priority
	})
	return &Engine{rules: out}
}

func (r *Rule) compile() bool {
	for _, p := range r.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return false
		}
		r.compiledPatterns = append(r.compiledPatterns, re)
	}
	r.compiledProduct = compileOrNil(r.ProductRegex)
	r.compiledVersion = compileOrNil(r.VersionRegex)
	r.compiledOS = compileOrNil(r.OSRegex)
	return true
}

func compileOrNil(expr string) *regexp.Regexp {
	if expr == "" {
		return nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil
	}
	return re
}

// Identify returns the best matching Result for a single input. If nothing
// matches it returns an "unknown" result; it never errors and never panics.
func (e *Engine) Identify(in Input) Result {
	res := Result{
		IP:       in.IP,
		Port:     in.Port,
		Protocol: "unknown",
	}
	for i := range e.rules {
		r := &e.rules[i]
		if !r.matches(in.Banner) {
			continue
		}
		res.Protocol = r.Protocol
		res.Product = r.extract(r.compiledProduct, r.Product, in.Banner)
		res.Version = r.extract(r.compiledVersion, r.Version, in.Banner)
		res.OSHint = r.extract(r.compiledOS, "", in.Banner)
		res.Confidence = r.Confidence
		break
	}
	return res
}

// IdentifyAll fingerprints a batch of inputs.
func (e *Engine) IdentifyAll(inputs []Input) []Result {
	out := make([]Result, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, e.Identify(in))
	}
	return out
}

func (r *Rule) matches(banner string) bool {
	for _, re := range r.compiledPatterns {
		if re.MatchString(banner) {
			return true
		}
	}
	return false
}

// extract returns capture group 1 of re when it matches, otherwise fallback.
func (r *Rule) extract(re *regexp.Regexp, fallback, banner string) string {
	if re == nil {
		return fallback
	}
	if m := re.FindStringSubmatch(banner); len(m) > 1 {
		return m[1]
	}
	return fallback
}

// hexEscapeRe matches the non-standard \xNN escape used by some scanners to
// encode arbitrary bytes inside a JSON string.
var hexEscapeRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// UnescapeHexEscape rewrites \xNN into the JSON-standard \u00NN form so the
// payload can be parsed by encoding/json. It is a no-op for valid JSON.
func UnescapeHexEscape(data []byte) []byte {
	return hexEscapeRe.ReplaceAllFunc(data, func(m []byte) []byte {
		return []byte("\\u00" + string(m[2:]))
	})
}
