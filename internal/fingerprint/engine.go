// Package fingerprint 实现了一个规则驱动的 Banner 指纹识别引擎。
//
// 引擎本身不包含任何协议相关的硬编码逻辑:所有识别决策都以数据的形式
// 写在 rules.json 中,该文件在编译期通过 go:embed 打进二进制,运行时也可
// 通过 RULES_FILE 环境变量指向外部规则文件,从而实现规则与代码的解耦。
package fingerprint

import (
	"regexp"
	"sort"
)

// Input 表示一条网络扫描的原始记录。
type Input struct {
	IP     string `json:"ip"`     // 目标主机 IP
	Port   int    `json:"port"`   // 目标端口
	Banner string `json:"banner"` // 服务返回的 banner 原始内容(可能含二进制字节)
}

// Result 表示一条识别结果。
type Result struct {
	IP         string  `json:"ip"`         // 原样回显的 IP
	Port       int     `json:"port"`       // 原样回显的端口
	Protocol   string  `json:"protocol"`   // 协议,识别失败时为 "unknown"
	Product    string  `json:"product"`    // 软件名
	Version    string  `json:"version"`    // 版本号
	OSHint     string  `json:"os_hint"`    // 操作系统提示(可从 banner 提取时)
	Confidence float64 `json:"confidence"` // 置信度 0~1
}

// Rule 描述一条指纹识别规则。所有匹配与字段提取都以声明式方式表达,
// 因此修改识别行为只需编辑 JSON 规则文件,而无需改动 Go 代码。
type Rule struct {
	Name         string   `json:"name"`                    // 规则名(便于调试)
	Protocol     string   `json:"protocol"`                // 命中的协议
	Priority     int      `json:"priority"`                // 优先级,越大越先匹配
	Patterns     []string `json:"patterns"`                // 匹配模式,命中任一即判定
	Product      string   `json:"product,omitempty"`       // 固定软件名(无 product_regex 时使用)
	ProductRegex string   `json:"product_regex,omitempty"` // 从 banner 提取软件名的正则
	Version      string   `json:"version,omitempty"`       // 固定版本号(无 version_regex 时使用)
	VersionRegex string   `json:"version_regex,omitempty"` // 从 banner 提取版本号的正则
	OSRegex      string   `json:"os_regex,omitempty"`      // 从 banner 提取操作系统提示的正则
	Confidence   float64  `json:"confidence"`              // 置信度 0~1

	// 以下为编译后的正则缓存,不参与 JSON 序列化
	compiledPatterns []*regexp.Regexp // 编译后的匹配模式
	compiledProduct  *regexp.Regexp   // 编译后的软件名正则
	compiledVersion  *regexp.Regexp   // 编译后的版本号正则
	compiledOS       *regexp.Regexp   // 编译后的系统提示正则
}

// Engine 依据一组有序规则对 banner 进行识别。
type Engine struct {
	rules []Rule // 按优先级降序排列的规则列表
}

// NewEngine 将给定规则编译成 Engine。规则按优先级降序排列,先命中的规则
// 直接返回结果。无效的正则会被跳过,而不是导致启动失败。
func NewEngine(rules []Rule) *Engine {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if !r.compile() { // 正则编译失败的规则直接丢弃
			continue
		}
		out = append(out, r)
	}
	// 按优先级从高到低排序,保证高优先级规则先被尝试
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Priority > out[j].Priority
	})
	return &Engine{rules: out}
}

// compile 预编译规则中的全部正则,任一匹配模式编译失败则整条规则作废。
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

// compileOrNil 编译一个正则表达式;为空串或编译失败时返回 nil。
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

// Identify 对单条输入返回最优匹配结果;无匹配时返回 "unknown" 结果。
// 该方法保证不会返回错误、不会 panic。
func (e *Engine) Identify(in Input) Result {
	// 默认结果:协议未知,其余字段留空,置信度为 0
	res := Result{
		IP:       in.IP,
		Port:     in.Port,
		Protocol: "unknown",
	}
	// 按优先级遍历规则,命中第一条即返回
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

// IdentifyAll 对一批输入进行批量识别。
func (e *Engine) IdentifyAll(inputs []Input) []Result {
	out := make([]Result, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, e.Identify(in))
	}
	return out
}

// matches 判断 banner 是否命中规则中的任一匹配模式。
func (r *Rule) matches(banner string) bool {
	for _, re := range r.compiledPatterns {
		if re.MatchString(banner) {
			return true
		}
	}
	return false
}

// extract 返回正则捕获组 1 的值;未命中或正则未编译时返回 fallback。
func (r *Rule) extract(re *regexp.Regexp, fallback, banner string) string {
	if re == nil {
		return fallback
	}
	if m := re.FindStringSubmatch(banner); len(m) > 1 {
		return m[1]
	}
	return fallback
}

// hexEscapeRe 匹配某些扫描器在 JSON 字符串中使用的非标准 \xNN 转义,
// 用于表示任意二进制字节。
var hexEscapeRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// UnescapeHexEscape 将 \xNN 重写为 JSON 标准的 \u00NN 形式,使带原始字节
// 转义的 JSON 能被 encoding/json 正常解析。对合法 JSON 而言该操作无副作用。
func UnescapeHexEscape(data []byte) []byte {
	return hexEscapeRe.ReplaceAllFunc(data, func(m []byte) []byte {
		return []byte("\\u00" + string(m[2:]))
	})
}
