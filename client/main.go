// Command client reads a local JSON file of scan records, sends them to the
// fingerprint server, and prints the results.
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
	file := flag.String("file", envOr("INPUT_FILE", "/data/sample.json"), "path to JSON input file (array of {ip,port,banner})")
	server := flag.String("server", envOr("FINGERPRINT_SERVER", "http://server:8080"), "fingerprint server base URL")
	asJSON := flag.Bool("json", false, "print results as JSON")
	flag.Parse()

	inputs, err := loadInputs(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load inputs: %v\n", err)
		os.Exit(1)
	}

	results, err := send(*server, inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	printTable(results)
}

func loadInputs(path string) ([]fingerprint.Input, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = fingerprint.UnescapeHexEscape(data)
	var inputs []fingerprint.Input
	if err := json.Unmarshal(data, &inputs); err != nil {
		return nil, err
	}
	return inputs, nil
}

func send(baseURL string, inputs []fingerprint.Input) ([]fingerprint.Result, error) {
	payload, err := json.Marshal(inputs)
	if err != nil {
		return nil, err
	}
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

func printTable(results []fingerprint.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
	}
	_ = w.Flush()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
