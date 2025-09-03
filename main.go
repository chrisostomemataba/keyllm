package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	defaultAdminEmail = "admin@local"
)

var dbPath = os.Getenv("DB_PATH")

func init() {
	if dbPath == "" {
		dbPath = "keyllm.db" // Default for local running
	}
}

var (
	db           *sql.DB
	adminTokens  = map[string]time.Time{}
	openAPISpec  = mustOpenAPISpec()
	serverStart  = time.Now()
	requestLimit = 10_000_000
)

func rndToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func parseInt(s string, def int) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return i
}

func clientIP(c *fiber.Ctx) string {
	ip := c.IP()
	if ip == "::1" {
		ip = "127.0.0.1"
	}
	return ip
}

func mustOpenDB() *sql.DB {
	d, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	d.Exec("PRAGMA journal_mode=WAL;")
	d.Exec("PRAGMA busy_timeout=5000;")
	return d
}

func mustMigrate() {
	schema := `
-- Enhanced settings (still single company but better organized)
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id=1),
  company_name TEXT DEFAULT 'KeyLLM',
  logo_url TEXT,
  admin_email TEXT DEFAULT 'admin@local',
  admin_password_hash TEXT,
  license_key TEXT,
  https_enabled INTEGER DEFAULT 0,
  max_daily_requests INTEGER DEFAULT 0,  -- Global rate limiting
  max_monthly_requests INTEGER DEFAULT 0,
  created_at TEXT,
  updated_at TEXT
);

INSERT INTO settings (id) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM settings WHERE id=1);

CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  label TEXT,
  owner TEXT,
  expires_at TEXT,
  daily_limit INTEGER DEFAULT 0,
  monthly_limit INTEGER DEFAULT 0,
  token_limit INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);

-- Multiple model configurations (remove single ID constraint)
CREATE TABLE IF NOT EXISTS model_configs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,                    -- User-friendly name
  backend TEXT DEFAULT 'ollama',         -- ollama|lmstudio|llamacpp|hf|custom  
  url TEXT DEFAULT 'http://localhost:11434',
  model_name TEXT DEFAULT 'llama2',
  temperature REAL DEFAULT 0.7,
  max_tokens INTEGER DEFAULT 512,
  headers_json TEXT DEFAULT '{}',
  is_active INTEGER DEFAULT 0,           -- Only one can be active
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key_id INTEGER,
  ts TEXT NOT NULL,
  prompt_chars INTEGER DEFAULT 0,
  completion_chars INTEGER DEFAULT 0,
  tokens INTEGER DEFAULT 0,
  model TEXT,
  latency_ms INTEGER DEFAULT 0,
  endpoint TEXT,
  FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
);


-- Separate IP allowlist table for better management
CREATE TABLE IF NOT EXISTS ip_allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL,              -- Individual IP or CIDR
  label TEXT,                            -- Description like "Office Network"
  created_at TEXT NOT NULL,
  is_active INTEGER DEFAULT 1
);
`
	if _, err := db.Exec(schema); err != nil { log.Fatal(err) }

	var has string
	_ = db.QueryRow("SELECT admin_password_hash FROM settings WHERE id=1").Scan(&has)
	if has == "" {
		password := os.Getenv("ADMIN_PASSWORD")
		if password == "" { password = "admin" } 
		hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		_, _ = db.Exec("UPDATE settings SET admin_password_hash=? WHERE id=1", string(hash))
		log.Println("admin password set (env ADMIN_PASSWORD or default 'admin')")
	}
}

func adminAuth(c *fiber.Ctx) error {
	auth := c.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return fiber.ErrUnauthorized
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	exp, ok := adminTokens[token]
	if !ok || time.Now().After(exp) {
		return fiber.ErrUnauthorized
	}
	return c.Next()
}

func ipAllowed(ip string) bool {
	// Get all active IPs from database
	rows, err := db.Query("SELECT ip_address FROM ip_allowlist WHERE is_active = 1")
	if err != nil {
		return true // Fail open if database error
	}
	defer rows.Close()

	var allowedIPs []string
	for rows.Next() {
		var allowedIP string
		_ = rows.Scan(&allowedIP)
		allowedIPs = append(allowedIPs, allowedIP)
	}

	// If no IPs configured, allow all
	if len(allowedIPs) == 0 {
		return true
	}

	// Check against each allowed IP/CIDR
	for _, allowedIP := range allowedIPs {
		allowedIP = strings.TrimSpace(allowedIP)
		if allowedIP == "" {
			continue
		}

		if strings.Contains(allowedIP, "/") {
			// CIDR range
			_, network, err := net.ParseCIDR(allowedIP)
			if err == nil && network.Contains(net.ParseIP(ip)) {
				return true
			}
		} else {
			// Single IP
			if ip == allowedIP {
				return true
			}
		}
	}

	return false
}

func apiKeyAuth(c *fiber.Ctx) (*struct {
	ID                int64
	Key, Label, Owner string
	ExpiresAt         *string
	DL, ML, TL        int
}, error) {
	k := c.Get("X-API-Key")
	if k == "" {
		return nil, fiber.ErrUnauthorized
	}
	row := db.QueryRow(`SELECT id,key,label,owner,expires_at,daily_limit,monthly_limit,token_limit
	                    FROM api_keys WHERE key=?`, k)
	var rec struct {
		ID                int64
		Key, Label, Owner string
		ExpiresAt         *string
		DL, ML, TL        int
	}
	if err := row.Scan(&rec.ID, &rec.Key, &rec.Label, &rec.Owner, &rec.ExpiresAt, &rec.DL, &rec.ML, &rec.TL); err != nil {
		return nil, fiber.ErrUnauthorized
	}
	if rec.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339, *rec.ExpiresAt)
		if err == nil && time.Now().After(t) {
			return nil, fiber.ErrUnauthorized
		}
	}
	return &rec, nil
}

func secured(summary string, response interface{}) map[string]interface{} {
	return map[string]interface{}{
		"summary": summary,
		"security": []map[string]interface{}{
			{"BearerAuth": []string{}},
		},
		"responses": map[string]interface{}{
			"200": response,
			"401": map[string]interface{}{
				"description": "Unauthorized",
			},
		},
	}
}

type LoginReq struct{ Email, Password string }
type KeyReq struct {
	Label                                string  `json:"label"`
	Owner                                string  `json:"owner"`
	ExpiresAt                            *string `json:"expires_at"`
	DailyLimit, MonthlyLimit, TokenLimit int     `json:"daily_limit","monthly_limit","token_limit"`
}
type ModelCfg struct {
	Backend string            `json:"backend"`
	URL     string            `json:"url"`
	Model   string            `json:"model_name"`
	Temp    float64           `json:"temperature"`
	MaxTok  int               `json:"max_tokens"`
	Headers map[string]string `json:"headers,omitempty"`
}
type GenReq struct {
	Prompt string                 `json:"prompt"`
	Params map[string]interface{} `json:"params,omitempty"`
}
type Settings struct {
	CompanyName string `json:"company_name"`
	LogoURL     string `json:"logo_url"`
	IPAllowlist string `json:"ip_allowlist"`
	AdminEmail  string `json:"admin_email"`
	HTTPS       bool   `json:"https_enabled"`
	LicenseKey  string `json:"license_key"`
}

func main() {
	migrateOnly := flag.Bool("migrate", false, "Run database migrations and exit")
	flag.Parse()

	db = mustOpenDB()
	defer db.Close()

	if *migrateOnly {
		fmt.Println("Running database migrations...")
		mustMigrate()
		fmt.Println("Migrations completed successfully.")
		return
	}

	mustMigrate()
	app := fiber.New()
	app.Use(cors.New())

	app.Use("/web", filesystem.New(filesystem.Config{
		Root: http.Dir("./web"),
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Redirect("/web/login.html")
	})

	app.Get("/docs", func(c *fiber.Ctx) error {
		html := `<!doctype html><html><head><meta charset=utf-8><title>KeyLLM API Docs</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.css">
</head><body>
<redoc spec-url='/openapi.json'></redoc>
<script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
</body></html>`
		return c.Type("html").SendString(html)
	})
	app.Get("/openapi.json", func(c *fiber.Ctx) error {
		return c.Type("json").Send(openAPISpec)
	})

	app.Post("/auth/login", func(c *fiber.Ctx) error {
		var r LoginReq
		if err := c.BodyParser(&r); err != nil {
			return fiber.ErrBadRequest
		}
		var email, hash string
		if err := db.QueryRow("SELECT admin_email, admin_password_hash FROM settings WHERE id=1").Scan(&email, &hash); err != nil {
			return fiber.ErrInternalServerError
		}
		if r.Email == "" {
			r.Email = email
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.Password)) != nil {
			return fiber.ErrUnauthorized
		}
		tok := rndToken(24)
		adminTokens[tok] = time.Now().Add(12 * time.Hour)
		return c.JSON(fiber.Map{"token": tok, "expires_in_hours": 12})
	})

	app.Get("/admin/keys", adminAuth, func(c *fiber.Ctx) error {
		rows, err := db.Query(`SELECT id,key,label,owner,expires_at,daily_limit,monthly_limit,token_limit,created_at FROM api_keys ORDER BY id DESC`)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		defer rows.Close()
		var out []map[string]interface{}
		for rows.Next() {
			var id int64
			var key, label, owner, created string
			var exp *string
			var dl, ml, tl int
			_ = rows.Scan(&id, &key, &label, &owner, &exp, &dl, &ml, &tl, &created)
			out = append(out, fiber.Map{"id": id, "key": key, "label": label, "owner": owner, "expires_at": exp, "daily_limit": dl, "monthly_limit": ml, "token_limit": tl, "created_at": created})
		}
		return c.JSON(out)
	})
	app.Post("/admin/keys", adminAuth, func(c *fiber.Ctx) error {
		var r KeyReq
		if err := c.BodyParser(&r); err != nil {
			return fiber.ErrBadRequest
		}
		k := "sk-" + rndToken(20)
		_, err := db.Exec(`INSERT INTO api_keys (key,label,owner,expires_at,daily_limit,monthly_limit,token_limit,created_at)
		                   VALUES (?,?,?,?,?,?,?,?)`,
			k, r.Label, r.Owner, r.ExpiresAt, r.DailyLimit, r.MonthlyLimit, r.TokenLimit, nowUTC())
		if err != nil {
			return fiber.ErrInternalServerError
		}
		var id int64
		_ = db.QueryRow(`SELECT id FROM api_keys WHERE key=?`, k).Scan(&id)
		return c.Status(201).JSON(fiber.Map{"id": id, "key": k})
	})
	app.Delete("/admin/keys/:id", adminAuth, func(c *fiber.Ctx) error {
		_, err := db.Exec("DELETE FROM api_keys WHERE id=?", c.Params("id"))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})

	app.Get("/admin/model", adminAuth, func(c *fiber.Ctx) error {
		var b, u, m string
		var t float64
		var mx int
		var hj string
		if err := db.QueryRow(`SELECT backend,url,model_name,temperature,max_tokens,headers_json FROM model_config WHERE id=1`).
			Scan(&b, &u, &m, &t, &mx, &hj); err != nil {
			return fiber.ErrInternalServerError
		}
		var hdrs map[string]string
		_ = json.Unmarshal([]byte(hj), &hdrs)
		return c.JSON(ModelCfg{Backend: b, URL: u, Model: m, Temp: t, MaxTok: mx, Headers: hdrs})
	})
	app.Put("/admin/model", adminAuth, func(c *fiber.Ctx) error {
		var r ModelCfg
		if err := c.BodyParser(&r); err != nil {
			return fiber.ErrBadRequest
		}
		if r.Headers == nil {
			r.Headers = map[string]string{}
		}
		hb, _ := json.Marshal(r.Headers)
		_, err := db.Exec(`UPDATE model_config SET backend=?,url=?,model_name=?,temperature=?,max_tokens=?,headers_json=? WHERE id=1`,
			r.Backend, r.URL, r.Model, r.Temp, r.MaxTok, string(hb))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})
	app.Post("/admin/model/test", adminAuth, func(c *fiber.Ctx) error {
		var url string
		_ = db.QueryRow(`SELECT url FROM model_config WHERE id=1`).Scan(&url)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return c.Status(502).JSON(fiber.Map{"ok": false, "error": err.Error()})
		}
		defer resp.Body.Close()
		return c.JSON(fiber.Map{"ok": resp.StatusCode < 500, "status": resp.Status})
	})

	app.Get("/admin/settings", adminAuth, func(c *fiber.Ctx) error {
		var s Settings
		var https int
		if err := db.QueryRow(`SELECT company_name,logo_url,ip_allowlist,admin_email,https_enabled,license_key FROM settings WHERE id=1`).
			Scan(&s.CompanyName, &s.LogoURL, &s.IPAllowlist, &s.AdminEmail, &https, &s.LicenseKey); err != nil {
			return fiber.ErrInternalServerError
		}
		s.HTTPS = https == 1
		return c.JSON(s)
	})
	app.Put("/admin/settings", adminAuth, func(c *fiber.Ctx) error {
		var s Settings
		if err := c.BodyParser(&s); err != nil {
			return fiber.ErrBadRequest
		}
		https := 0
		if s.HTTPS {
			https = 1
		}
		_, err := db.Exec(`UPDATE settings SET company_name=?,logo_url=?,ip_allowlist=?,admin_email=?,https_enabled=?,license_key=? WHERE id=1`,
			s.CompanyName, s.LogoURL, s.IPAllowlist, s.AdminEmail, https, s.LicenseKey)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})

	app.Get("/admin/logs", adminAuth, func(c *fiber.Ctx) error {
		limit := parseInt(c.Query("limit", "100"), 100)
		offset := parseInt(c.Query("offset", "0"), 0)
		rows, err := db.Query(`SELECT id,api_key_id,ts,prompt_chars,completion_chars,tokens,model,latency_ms,endpoint
		                       FROM usage_logs ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		defer rows.Close()
		var out []map[string]interface{}
		for rows.Next() {
			var id, apiKeyID, p, comp, tok, lat int
			var ts, model, ep string
			_ = rows.Scan(&id, &apiKeyID, &ts, &p, &comp, &tok, &model, &lat, &ep)
			out = append(out, fiber.Map{"id": id, "api_key_id": apiKeyID, "ts": ts, "prompt_chars": p, "completion_chars": comp, "tokens": tok, "model": model, "latency_ms": lat, "endpoint": ep})
		}
		return c.JSON(out)
	})
	app.Get("/admin/logs/export", adminAuth, func(c *fiber.Ctx) error {
		rows, err := db.Query(`SELECT id,api_key_id,ts,prompt_chars,completion_chars,tokens,model,latency_ms,endpoint
		                       FROM usage_logs ORDER BY id DESC LIMIT ?`, requestLimit)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		defer rows.Close()
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		_ = w.Write([]string{"id", "api_key_id", "ts", "prompt_chars", "completion_chars", "tokens", "model", "latency_ms", "endpoint"})
		for rows.Next() {
			var id, apiKeyID, p, comp, tok, lat int
			var ts, model, ep string
			_ = rows.Scan(&id, &apiKeyID, &ts, &p, &comp, &tok, &model, &lat, &ep)
			_ = w.Write([]string{
				strconv.Itoa(id), strconv.Itoa(apiKeyID), ts,
				strconv.Itoa(p), strconv.Itoa(comp), strconv.Itoa(tok),
				model, strconv.Itoa(lat), ep,
			})
		}
		w.Flush()
		c.Set("Content-Type", "text/csv")
		c.Attachment("usage_logs.csv")
		return c.Send(buf.Bytes())
	})

	app.Post("/llm/generate", func(c *fiber.Ctx) error {
		var allowlist string
		_ = db.QueryRow("SELECT ip_allowlist FROM settings WHERE id=1").Scan(&allowlist)
		if !ipAllowed(clientIP(c)) {
			return fiber.ErrForbidden
		}

		ak, err := apiKeyAuth(c)
		if err != nil {
			return err
		}

		var cfg ModelCfg
		var hj string
		_ = db.QueryRow(`SELECT backend,url,model_name,temperature,max_tokens,headers_json FROM model_config WHERE id=1`).
			Scan(&cfg.Backend, &cfg.URL, &cfg.Model, &cfg.Temp, &cfg.MaxTok, &hj)
		_ = json.Unmarshal([]byte(hj), &cfg.Headers)

		var r GenReq
		if err := c.BodyParser(&r); err != nil {
			return fiber.ErrBadRequest
		}
		prompt := r.Prompt
		if prompt == "" {
			return fiber.NewError(400, "prompt required")
		}

		start := time.Now()
		var outText string
		switch strings.ToLower(cfg.Backend) {
		case "ollama":
			body := map[string]interface{}{"model": cfg.Model, "prompt": prompt, "options": map[string]interface{}{"temperature": cfg.Temp}}
			b, _ := json.Marshal(body)
			req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.URL, "/")+"/api/generate", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			for k, v := range cfg.Headers {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fiber.NewError(502, err.Error())
			}
			defer resp.Body.Close()
			var j map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&j)
			if s, ok := j["response"].(string); ok {
				outText = s
			} else {
				outText = fmt.Sprintf("%v", j)
			}

		case "lmstudio", "openai", "openai_compat":
			payload := map[string]interface{}{
				"model":       cfg.Model,
				"messages":    []map[string]string{{"role": "user", "content": prompt}},
				"temperature": cfg.Temp,
				"max_tokens":  cfg.MaxTok,
			}
			b, _ := json.Marshal(payload)
			u := strings.TrimRight(cfg.URL, "/") + "/v1/chat/completions"
			req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			for k, v := range cfg.Headers {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fiber.NewError(502, err.Error())
			}
			defer resp.Body.Close()
			var j struct {
				Choices []struct {
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
				} `json:"choices"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&j)
			if len(j.Choices) > 0 {
				outText = j.Choices[0].Message.Content
			}

		default:
			return fiber.NewError(400, "unsupported backend: "+cfg.Backend)
		}

		lat := time.Since(start).Milliseconds()
		toks := (len(prompt) + len(outText)) / 4

		_, _ = db.Exec(`INSERT INTO usage_logs (api_key_id,ts,prompt_chars,completion_chars,tokens,model,latency_ms,endpoint)
		                VALUES (?,?,?,?,?,?,?,?)`,
			ak.ID, nowUTC(), len(prompt), len(outText), toks, cfg.Model, lat, "/llm/generate")

		return c.JSON(fiber.Map{"model": cfg.Model, "latency_ms": lat, "tokens_est": toks, "output": outText})
	})
	app.Get("/admin/models", adminAuth, func(c *fiber.Ctx) error {
		rows, err := db.Query(`SELECT id,name,backend,url,model_name,temperature,max_tokens,is_active,created_at FROM model_configs ORDER BY id DESC`)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		defer rows.Close()

		var models []map[string]interface{}
		for rows.Next() {
			var id int64
			var name, backend, url, model, created string
			var temp float64
			var maxTok, active int
			_ = rows.Scan(&id, &name, &backend, &url, &model, &temp, &maxTok, &active, &created)

			models = append(models, fiber.Map{
				"id": id, "name": name, "backend": backend, "url": url,
				"model_name": model, "temperature": temp, "max_tokens": maxTok,
				"is_active": active == 1, "created_at": created,
			})
		}
		return c.JSON(models)
	})

	app.Post("/admin/models", adminAuth, func(c *fiber.Ctx) error {
		var req struct {
			Name        string  `json:"name"`
			Backend     string  `json:"backend"`
			URL         string  `json:"url"`
			ModelName   string  `json:"model_name"`
			Temperature float64 `json:"temperature"`
			MaxTokens   int     `json:"max_tokens"`
			IsActive    bool    `json:"is_active"`
		}

		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		// If setting as active, deactivate others
		if req.IsActive {
			_, _ = db.Exec("UPDATE model_configs SET is_active = 0")
		}

		active := 0
		if req.IsActive {
			active = 1
		}

		_, err := db.Exec(`INSERT INTO model_configs (name,backend,url,model_name,temperature,max_tokens,is_active,created_at)
						   VALUES (?,?,?,?,?,?,?,?)`,
			req.Name, req.Backend, req.URL, req.ModelName, req.Temperature, req.MaxTokens, active, nowUTC())

		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(201)
	})

	app.Delete("/admin/models/:id", adminAuth, func(c *fiber.Ctx) error {
		_, err := db.Exec("DELETE FROM model_configs WHERE id = ?", c.Params("id"))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})

	app.Put("/admin/models/:id/activate", adminAuth, func(c *fiber.Ctx) error {
		id := c.Params("id")

		// Deactivate all others first
		_, _ = db.Exec("UPDATE model_configs SET is_active = 0")

		// Activate the selected one
		_, err := db.Exec("UPDATE model_configs SET is_active = 1 WHERE id = ?", id)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		return c.SendStatus(204)
	})

	// IP Management Endpoints
	app.Get("/admin/ips", adminAuth, func(c *fiber.Ctx) error {
		rows, err := db.Query(`SELECT id,ip_address,label,is_active,created_at FROM ip_allowlist ORDER BY id DESC`)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		defer rows.Close()

		var ips []map[string]interface{}
		for rows.Next() {
			var id int64
			var ip, label, created string
			var active int
			_ = rows.Scan(&id, &ip, &label, &active, &created)

			ips = append(ips, fiber.Map{
				"id": id, "ip_address": ip, "label": label,
				"is_active": active == 1, "created_at": created,
			})
		}
		return c.JSON(ips)
	})

	app.Post("/admin/ips", adminAuth, func(c *fiber.Ctx) error {
		var req struct {
			IPAddress string `json:"ip_address"`
			Label     string `json:"label"`
		}

		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		// Validate IP/CIDR format
		if req.IPAddress != "" {
			if !strings.Contains(req.IPAddress, "/") {
				// Single IP
				if net.ParseIP(req.IPAddress) == nil {
					return fiber.NewError(400, "Invalid IP address")
				}
			} else {
				// CIDR range
				if _, _, err := net.ParseCIDR(req.IPAddress); err != nil {
					return fiber.NewError(400, "Invalid CIDR range")
				}
			}
		}

		_, err := db.Exec(`INSERT INTO ip_allowlist (ip_address,label,created_at,is_active) VALUES (?,?,?,1)`,
			req.IPAddress, req.Label, nowUTC())

		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(201)
	})

	app.Delete("/admin/ips/:id", adminAuth, func(c *fiber.Ctx) error {
		_, err := db.Exec("DELETE FROM ip_allowlist WHERE id = ?", c.Params("id"))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})

	app.Put("/admin/ips/:id/toggle", adminAuth, func(c *fiber.Ctx) error {
		_, err := db.Exec("UPDATE ip_allowlist SET is_active = 1 - is_active WHERE id = ?", c.Params("id"))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "started_at": serverStart.Format(time.RFC3339)})
	})

	log.Println("KeyLLM server listening on :8080")
	log.Fatal(app.Listen(":8080"))
}

func mustOpenAPISpec() []byte {
	spec := map[string]interface{}{
		"openapi": "3.0.0",
		"info":    map[string]string{"title": "KeyLLM API", "version": "1.0.0"},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"BearerAuth": map[string]interface{}{
					"type":   "http",
					"scheme": "bearer",
				},
			},
		},
		"paths": map[string]interface{}{
			"/auth/login": map[string]interface{}{"post": map[string]interface{}{
				"summary": "Admin login", "requestBody": reqObj(map[string]string{"email": "string", "password": "string"}),
				"responses": map[string]interface{}{"200": respObj(map[string]string{"token": "string", "expires_in_hours": "integer"})},
			}},
			"/admin/keys": map[string]interface{}{
				"get":  secured("List keys", respArr(obj(map[string]string{"id": "integer", "key": "string", "label": "string", "owner": "string"}))),
				"post": secured("Create key", respObj(map[string]string{"id": "integer", "key": "string"})),
			},
			"/admin/keys/{id}": map[string]interface{}{
				"delete": secured("Delete key", map[string]interface{}{"description": "No Content", "content": map[string]interface{}{}}),
			},
			"/admin/model": map[string]interface{}{
				"get": secured("Get model config", respObj(map[string]string{"backend": "string", "url": "string", "model_name": "string"})),
				"put": secured("Update model config", respEmpty()),
			},
			"/admin/model/test": map[string]interface{}{"post": secured("Test model endpoint", respObj(map[string]string{"ok": "boolean", "status": "string"}))},
			"/admin/settings": map[string]interface{}{
				"get": secured("Get settings", respObj(map[string]string{"company_name": "string", "ip_allowlist": "string"})),
				"put": secured("Update settings", respEmpty()),
			},
			"/admin/logs":        map[string]interface{}{"get": secured("List usage logs", respArr(obj(map[string]string{"id": "integer", "ts": "string", "tokens": "integer"})))},
			"/admin/logs/export": map[string]interface{}{"get": secured("Export CSV", respText("text/csv"))},
			"/llm/generate": map[string]interface{}{"post": map[string]interface{}{
				"summary":     "Generate via API key",
				"parameters":  []map[string]interface{}{{"name": "X-API-Key", "in": "header", "required": true, "schema": map[string]string{"type": "string"}}},
				"requestBody": reqObj(map[string]string{"prompt": "string"}),
				"responses":   map[string]interface{}{"200": respObj(map[string]string{"output": "string", "tokens_est": "integer", "latency_ms": "integer"})},
			}},
			"/health": map[string]interface{}{"get": map[string]interface{}{"summary": "Health", "responses": map[string]interface{}{"200": respObj(map[string]string{"status": "string"})}}},
		},
	}
	b, _ := json.MarshalIndent(spec, "", "  ")
	return b
}

func obj(props map[string]string) map[string]interface{} {
	m := map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
	for k, t := range props {
		m["properties"].(map[string]interface{})[k] = map[string]string{"type": t}
	}
	return m
}
func respObj(props map[string]string) map[string]interface{} {
	return map[string]interface{}{"description": "OK", "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": obj(props)}}}
}
func respArr(schema map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"description": "OK", "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "array", "items": schema}}}}
}
func respText(ct string) map[string]interface{} {
	return map[string]interface{}{"description": "OK", "content": map[string]interface{}{ct: map[string]interface{}{"schema": map[string]string{"type": "string"}}}}
}
func reqObj(props map[string]string) map[string]interface{} {
	return map[string]interface{}{"required": true, "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": obj(props)}}}
}
func respEmpty() map[string]interface{} { return map[string]interface{}{"description": "No Content"} }
