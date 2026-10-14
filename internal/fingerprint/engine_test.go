package fingerprint

import (
	"encoding/json"
	"testing"
)

func TestIdentify(t *testing.T) {
	e, err := LoadDefaultRules()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	cases := []struct {
		name     string
		input    Input
		protocol string
		product  string
		version  string
		os       string
	}{
		{"ssh-ubuntu", Input{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "SSH", "OpenSSH", "8.9p1", "Ubuntu"},
		{"ssh-debian", Input{IP: "1.2.3.11", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"}, "SSH", "OpenSSH", "9.3", "Debian"},
		{"ssh-old", Input{IP: "1.2.3.18", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"}, "SSH", "OpenSSH", "4.3", ""},
		{"http-nginx", Input{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, "HTTP", "nginx", "1.24.0", ""},
		{"http-apache", Input{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, "HTTP", "Apache", "2.4.57", ""},
		{"http-jetty", Input{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, "HTTP", "Jetty", "9.4.51", ""},
		{"http-iis", Input{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, "HTTP", "Microsoft-IIS", "10.0", ""},
		{"http-nginx-ubuntu", Input{IP: "1.2.3.12", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"}, "HTTP", "nginx", "1.18.0", "Ubuntu"},
		{"mysql-8", Input{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"}, "MySQL", "MySQL", "8.0.32", ""},
		{"mysql-5", Input{IP: "1.2.3.14", Port: 3306, Banner: "J\x00\x00\x00\n5.7.42\x00"}, "MySQL", "MySQL", "5.7.42", ""},
		{"redis-err", Input{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"}, "Redis", "Redis", "", ""},
		{"redis-pong", Input{IP: "1.2.3.15", Port: 6379, Banner: "+PONG"}, "Redis", "Redis", "", ""},
		{"redis-noauth", Input{IP: "1.2.3.21", Port: 6379, Banner: "-NOAUTH Authentication required."}, "Redis", "Redis", "", ""},
		{"ftp-proftpd", Input{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", ""},
		{"ftp-vsftpd", Input{IP: "1.2.3.16", Port: 21, Banner: "220 (vsFTPd 3.0.5)"}, "FTP", "vsFTPd", "3.0.5", ""},
		{"ftp-pureftpd", Input{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"}, "FTP", "Pure-FTPd", "", ""},
		{"tls", Input{IP: "1.2.3.19", Port: 9999, Banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}, "TLS", "TLS", "", ""},
		{"unknown", Input{IP: "1.2.3.23", Port: 12345, Banner: "QUIT\r\n"}, "unknown", "", "", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := e.Identify(c.input)
			if got.Protocol != c.protocol {
				t.Errorf("protocol = %q, want %q", got.Protocol, c.protocol)
			}
			if got.Product != c.product {
				t.Errorf("product = %q, want %q", got.Product, c.product)
			}
			if got.Version != c.version {
				t.Errorf("version = %q, want %q", got.Version, c.version)
			}
			if got.OSHint != c.os {
				t.Errorf("os_hint = %q, want %q", got.OSHint, c.os)
			}
		})
	}
}

// TestEngineNeverPanics ensures arbitrary (including empty/binary) banners can
// never crash the engine.
func TestEngineNeverPanics(t *testing.T) {
	e, _ := LoadDefaultRules()
	banners := []string{"", "\x00\x00\x00", "\x16\x03\x01", "HTTP/1.1 200", "220", "-ERR", "SSH-2.0-", "garbage\r\n", "\xff\xfe\xfd"}
	for _, b := range banners {
		res := e.Identify(Input{IP: "0.0.0.0", Port: 1, Banner: b})
		if res.Protocol == "" {
			t.Errorf("empty protocol for banner %q", b)
		}
	}
}

// TestUnescapeHexEscape verifies the non-standard \xNN -> \u00NN rewrite that
// lets JSON with raw-byte escapes be parsed.
func TestUnescapeHexEscape(t *testing.T) {
	raw := []byte(`[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`)
	data := UnescapeHexEscape(raw)
	var inputs []Input
	if err := json.Unmarshal(data, &inputs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(inputs) != 1 {
		t.Fatalf("len = %d, want 1", len(inputs))
	}
	want := "J\x00\x00\x00\n8.0.32\x00"
	if inputs[0].Banner != want {
		t.Errorf("banner = %q, want %q", inputs[0].Banner, want)
	}
}
