// Command server 通过 HTTP 对外提供指纹识别服务。
//
// 接口:
//
//	GET  /health       健康检查,供容器编排探活使用
//	POST /fingerprint  批量识别,请求体为 {ip,port,banner} 的 JSON 数组
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"banner/internal/fingerprint"
)

// maxBody 限制请求体大小,防止恶意超大请求耗尽内存。
const maxBody = 32 << 20 // 32 MiB

// engine 全局识别引擎,启动时加载一次。
var engine *fingerprint.Engine

func main() {
	// 加载识别规则(内嵌或 RULES_FILE 指定)
	e, err := fingerprint.LoadDefaultRules()
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}
	engine = e

	// 注册路由
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/fingerprint", handleFingerprint)

	// 配置 HTTP 服务器与各类超时
	addr := ":" + envOr("PORT", "8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           logMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,  // 读请求头超时
		ReadTimeout:       30 * time.Second, // 读整个请求体超时
		WriteTimeout:      30 * time.Second, // 写响应超时
		IdleTimeout:       60 * time.Second, // 空闲连接超时
	}

	// 异步启动服务
	go func() {
		log.Printf("fingerprint server listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	// 监听 SIGINT/SIGTERM 信号,实现优雅停机
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	// 预留 10 秒处理存量请求后关闭
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Println("server stopped")
}

// handleHealth 处理健康检查请求,返回固定 JSON。
func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleFingerprint 处理批量识别请求:解析 JSON 数组 → 识别 → 返回结果数组。
func handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体,并限制大小
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return
	}
	// 容忍某些扫描器输出的非标准 \xNN 转义
	body = fingerprint.UnescapeHexEscape(body)

	// 解析为输入数组
	var inputs []fingerprint.Input
	if err := json.Unmarshal(body, &inputs); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	// 识别并编码返回
	results := engine.IdentifyAll(inputs)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		log.Printf("encode response: %v", err)
	}
}

// envOr 返回环境变量 key 的值,未设置时返回默认值 def。
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// logMiddleware 记录每个请求的来源、方法、路径与耗时。
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s (%s)", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start))
	})
}
