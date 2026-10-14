// Command client 读取本地 JSON 扫描数据文件,发送给指纹识别服务,并打印结果。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"banner/internal/fingerprint"
)

func main() {
	// 解析命令行参数
	file := flag.String("file", envOr("INPUT_FILE", "/data/sample.json"), "输入 JSON 文件路径({ip,port,banner} 数组)")
	server := flag.String("server", envOr("FINGERPRINT_SERVER", "http://server:8080"), "指纹识别服务的基础 URL")
	asJSON := flag.Bool("json", false, "以 JSON 格式打印结果")
	flag.Parse()

	// 1. 读取本地输入文件
	inputs, err := loadInputs(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load inputs: %v\n", err)
		os.Exit(1)
	}

	// 2. 发送到服务端进行识别
	results, err := send(*server, inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}

	// 3. 打印结果(JSON 或表格)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	printTable(results)
}

// loadInputs 读取并解析输入 JSON 文件为 []Input。
func loadInputs(path string) ([]fingerprint.Input, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// 容忍非标准 \xNN 转义后再按标准 JSON 解析
	data = fingerprint.UnescapeHexEscape(data)
	var inputs []fingerprint.Input
	if err := json.Unmarshal(data, &inputs); err != nil {
		return nil, err
	}
	return inputs, nil
}

// send 将输入 POST 到服务端 /fingerprint,并解析返回的结果。
func send(baseURL string, inputs []fingerprint.Input) ([]fingerprint.Result, error) {
	payload, err := json.Marshal(inputs)
	if err != nil {
		return nil, err
	}
	// 设置请求超时,避免服务端无响应时长时间阻塞
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(baseURL+"/fingerprint", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var results []fingerprint.Result
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}
	return results, nil
}

// printTable 以对齐表格形式打印识别结果。
func printTable(results []fingerprint.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
	}
	_ = w.Flush()
}

// envOr 返回环境变量 key 的值,未设置时返回默认值 def。
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
