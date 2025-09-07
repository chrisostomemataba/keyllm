package main

import (
	"bytes"
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
	"crypto/rand"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
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
)

// --- HELPER FUNCTIONS (RESTORED) ---
func rndToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }


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

// --- SCHEMA & MIGRATIONS ---
func mustMigrate() {
	schema := `
	CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY CHECK (id=1),
		company_name TEXT DEFAULT 'KeyLLM',
		logo_url TEXT,
		admin_email TEXT DEFAULT 'admin@local',
		admin_password_hash TEXT,
		license_key TEXT
	);

	INSERT INTO settings (id) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM settings WHERE id=1);

	CREATE TABLE IF NOT EXISTS model_configs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		backend TEXT DEFAULT 'ollama',
		url TEXT DEFAULT 'http://localhost:11434',
		model_name TEXT DEFAULT 'llama2',
		temperature REAL DEFAULT 0.7,
		max_tokens INTEGER DEFAULT 512,
		headers_json TEXT DEFAULT '{}',
		created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT UNIQUE NOT NULL,
		label TEXT,
		owner TEXT,
		model_id INTEGER NOT NULL,
		expires_at TEXT,
		daily_limit INTEGER DEFAULT 0,
		token_limit INTEGER DEFAULT 0,
		created_at TEXT NOT NULL,
		FOREIGN KEY(model_id) REFERENCES model_configs(id) ON DELETE CASCADE
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

	CREATE TABLE IF NOT EXISTS ip_allowlist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address TEXT NOT NULL,
		label TEXT,
		created_at TEXT NOT NULL,
		is_active INTEGER DEFAULT 1
	);
`
	if _, err := db.Exec(schema); err != nil {
		log.Fatal(err)
	}

	var has string
	_ = db.QueryRow("SELECT admin_password_hash FROM settings WHERE id=1").Scan(&has)
	if has == "" {
		password := os.Getenv("ADMIN_PASSWORD")
		if password == "" {
			password = "admin"
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		_, _ = db.Exec("UPDATE settings SET admin_password_hash=? WHERE id=1", string(hash))
		log.Println("Default admin password set to 'admin'")
	}
}

// --- AUTH MIDDLEWARE ---
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
	rows, err := db.Query("SELECT ip_address FROM ip_allowlist WHERE is_active = 1")
	if err != nil {
		return true // Fail open
	}
	defer rows.Close()
	var allowedIPs []string
	for rows.Next() {
		var allowedIP string
		_ = rows.Scan(&allowedIP)
		allowedIPs = append(allowedIPs, allowedIP)
	}
	if len(allowedIPs) == 0 {
		return true
	}
	for _, allowedIP := range allowedIPs {
		allowedIP = strings.TrimSpace(allowedIP)
		if strings.Contains(allowedIP, "/") {
			_, network, err := net.ParseCIDR(allowedIP)
			if err == nil && network.Contains(net.ParseIP(ip)) {
				return true
			}
		} else {
			if ip == allowedIP {
				return true
			}
		}
	}
	return false
}

func apiKeyAuth(c *fiber.Ctx) (*struct {
	ID        int64
	ModelID   int64
	Key       string
	ExpiresAt *string
}, error) {
	k := c.Get("X-API-Key")
	if k == "" {
		return nil, fiber.ErrUnauthorized
	}
	row := db.QueryRow(`SELECT id, model_id, key, expires_at FROM api_keys WHERE key=?`, k)
	var rec struct {
		ID        int64
		ModelID   int64
		Key       string
		ExpiresAt *string
	}
	if err := row.Scan(&rec.ID, &rec.ModelID, &rec.Key, &rec.ExpiresAt); err != nil {
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

// --- STRUCTS ---
type LoginReq struct{ Email, Password string }
type KeyReq struct {
	Label   string `json:"label"`
	Owner   string `json:"owner"`
	ModelID int64  `json:"model_id"`
}
type ModelCfg struct {
	ID      int64             `json:"id"`
	Name    string            `json:"name"`
	Backend string            `json:"backend"`
	URL     string            `json:"url"`
	Model   string            `json:"model_name"`
	Temp    float64           `json:"temperature"`
	MaxTok  int               `json:"max_tokens"`
	Headers map[string]string `json:"headers,omitempty"`
}
type GenReq struct {
	Prompt string `json:"prompt"`
}

// --- MAIN FUNCTION & ROUTES ---
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

	app.Get("/docs/spec.json", func(c *fiber.Ctx) error {
		return c.Type("json").Send(openAPISpec)
	})

	app.Post("/auth/login", func(c *fiber.Ctx) error {
		var r LoginReq
		if err := c.BodyParser(&r); err != nil {
			return fiber.ErrBadRequest
		}
		var email, hash string
		_ = db.QueryRow("SELECT admin_email, admin_password_hash FROM settings WHERE id=1").Scan(&email, &hash)
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.Password)) != nil {
			return fiber.ErrUnauthorized
		}
		tok := rndToken(24)
		adminTokens[tok] = time.Now().Add(12 * time.Hour)
		return c.JSON(fiber.Map{"token": tok})
	})

	// --- ADMIN GROUP ---
	admin := app.Group("/admin", adminAuth)

	// MODELS
	admin.Get("/models", func(c *fiber.Ctx) error {
		rows, _ := db.Query(`SELECT id, name, backend, url, model_name, temperature, max_tokens, created_at FROM model_configs ORDER BY id DESC`)
		defer rows.Close()
		var models []ModelCfg
		for rows.Next() {
			var m ModelCfg
			var created, headersJson string
			_ = rows.Scan(&m.ID, &m.Name, &m.Backend, &m.URL, &m.Model, &m.Temp, &m.MaxTok, &headersJson, &created)
			models = append(models, m)
		}
		return c.JSON(models)
	})
	admin.Post("/models", func(c *fiber.Ctx) error {
		var m ModelCfg
		_ = c.BodyParser(&m)
		hb, _ := json.Marshal(m.Headers)
		_, err := db.Exec(`INSERT INTO model_configs (name, backend, url, model_name, temperature, max_tokens, headers_json, created_at) VALUES (?,?,?,?,?,?,?,?)`,
			m.Name, m.Backend, m.URL, m.Model, m.Temp, m.MaxTok, string(hb), nowUTC())
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(201)
	})
	admin.Delete("/models/:id", func(c *fiber.Ctx) error {
		_, err := db.Exec("DELETE FROM model_configs WHERE id = ?", c.Params("id"))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})
	admin.Post("/models/:id/chat", func(c *fiber.Ctx) error {
		var r GenReq
		_ = c.BodyParser(&r)
		var cfg ModelCfg
		var hj string
		err := db.QueryRow(`SELECT id, name, backend, url, model_name, temperature, max_tokens, headers_json FROM model_configs WHERE id = ?`, c.Params("id")).
			Scan(&cfg.ID, &cfg.Name, &cfg.Backend, &cfg.URL, &cfg.Model, &cfg.Temp, &cfg.MaxTok, &hj)
		if err != nil {
			return fiber.NewError(404, "Model configuration not found")
		}
		_ = json.Unmarshal([]byte(hj), &cfg.Headers)
		outText, err := callLLM(cfg, r.Prompt)
		if err != nil {
			return fiber.NewError(502, err.Error())
		}
		return c.JSON(fiber.Map{"output": outText})
	})

	admin.Post("/models/test", func(c *fiber.Ctx) error {
		var cfg ModelCfg
		if err := c.BodyParser(&cfg); err != nil {
			return fiber.ErrBadRequest
		}

		if cfg.URL == "" {
			return fiber.NewError(400, "URL is required for testing")
		}

		client := http.Client{
			Timeout: 5 * time.Second, // 5-second timeout for the test
		}

		// A simple GET request is enough to verify the endpoint is reachable
		resp, err := client.Get(cfg.URL)
		if err != nil {
			return c.JSON(fiber.Map{
				"ok":    false,
				"error": "Connection failed: " + err.Error(),
			})
		}
		defer resp.Body.Close()

		// A status code less than 500 means the server is running and reachable.
		return c.JSON(fiber.Map{
			"ok":     resp.StatusCode < 500,
			"status": resp.Status,
		})
	})

	// KEYS
	admin.Get("/keys", func(c *fiber.Ctx) error {
		rows, _ := db.Query(`SELECT k.id, k.key, k.label, k.owner, k.model_id, m.name as model_name FROM api_keys k JOIN model_configs m ON k.model_id = m.id ORDER BY k.id DESC`)
		defer rows.Close()
		var keys []map[string]interface{}
		for rows.Next() {
			var id, model_id int64
			var key, label, owner, model_name string
			_ = rows.Scan(&id, &key, &label, &owner, &model_id, &model_name)
			keys = append(keys, fiber.Map{"id": id, "key": key, "label": label, "owner": owner, "model_id": model_id, "model_name": model_name})
		}
		return c.JSON(keys)
	})
	admin.Post("/keys", func(c *fiber.Ctx) error {
		var r KeyReq
		_ = c.BodyParser(&r)
		if r.ModelID == 0 {
			return fiber.NewError(400, "model_id is required")
		}
		k := "sk-" + rndToken(20)
		_, err := db.Exec(`INSERT INTO api_keys (key, label, owner, model_id, created_at) VALUES (?,?,?,?,?)`,
			k, r.Label, r.Owner, r.ModelID, nowUTC())
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(201)
	})
	admin.Delete("/keys/:id", func(c *fiber.Ctx) error {
		_, err := db.Exec("DELETE FROM api_keys WHERE id = ?", c.Params("id"))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})

	// LOGS
	admin.Get("/logs", func(c *fiber.Ctx) error {
		rows, _ := db.Query(`SELECT id, api_key_id, ts, tokens, model, latency_ms FROM usage_logs ORDER BY id DESC LIMIT 100`)
		defer rows.Close()
		var logs []map[string]interface{}
		for rows.Next() {
			var id, apiKeyID, tokens, lat int
			var ts, model string
			_ = rows.Scan(&id, &apiKeyID, &ts, &tokens, &model, &lat)
			logs = append(logs, fiber.Map{"id": id, "api_key_id": apiKeyID, "ts": ts, "tokens": tokens, "model": model, "latency_ms": lat})
		}
		return c.JSON(logs)
	})
	admin.Get("/logs/export", func(c *fiber.Ctx) error {
		rows, _ := db.Query(`SELECT id, api_key_id, ts, tokens, model, latency_ms FROM usage_logs ORDER BY id DESC`)
		defer rows.Close()
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		_ = w.Write([]string{"id", "api_key_id", "ts", "tokens", "model", "latency_ms"})
		for rows.Next() {
			var id, apiKeyID, tokens, lat int
			var ts, model string
			_ = rows.Scan(&id, &apiKeyID, &ts, &tokens, &model, &lat)
			_ = w.Write([]string{strconv.Itoa(id), strconv.Itoa(apiKeyID), ts, strconv.Itoa(tokens), model, strconv.Itoa(lat)})
		}
		w.Flush()
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", `attachment; filename="keyllm_usage_logs.csv"`)
		return c.Send(buf.Bytes())
	})

	// IP ALLOWLIST
	admin.Get("/ips", func(c *fiber.Ctx) error {
		rows, _ := db.Query(`SELECT id, ip_address, label, is_active FROM ip_allowlist ORDER BY id DESC`)
		defer rows.Close()
		var ips []map[string]interface{}
		for rows.Next() {
			var id int64
			var ip, label string
			var active bool
			_ = rows.Scan(&id, &ip, &label, &active)
			ips = append(ips, fiber.Map{"id": id, "ip_address": ip, "label": label, "is_active": active})
		}
		return c.JSON(ips)
	})
	admin.Post("/ips", func(c *fiber.Ctx) error {
		var req struct {
			IPAddress string `json:"ip_address"`
			Label     string `json:"label"`
		}
		_ = c.BodyParser(&req)
		_, err := db.Exec(`INSERT INTO ip_allowlist (ip_address, label, created_at, is_active) VALUES (?,?,?,1)`, req.IPAddress, req.Label, nowUTC())
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(201)
	})
	admin.Delete("/ips/:id", func(c *fiber.Ctx) error {
		_, err := db.Exec("DELETE FROM ip_allowlist WHERE id = ?", c.Params("id"))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})
	admin.Put("/ips/:id/toggle", func(c *fiber.Ctx) error {
		_, err := db.Exec("UPDATE ip_allowlist SET is_active = 1 - is_active WHERE id = ?", c.Params("id"))
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(204)
	})

	// --- PUBLIC API ---
	app.Post("/llm/generate", func(c *fiber.Ctx) error {
		if !ipAllowed(clientIP(c)) {
			return fiber.ErrForbidden
		}
		ak, err := apiKeyAuth(c)
		if err != nil {
			return err
		}
		var cfg ModelCfg
		var hj string
		err = db.QueryRow(`SELECT id, name, backend, url, model_name, temperature, max_tokens, headers_json FROM model_configs WHERE id = ?`, ak.ModelID).
			Scan(&cfg.ID, &cfg.Name, &cfg.Backend, &cfg.URL, &cfg.Model, &cfg.Temp, &cfg.MaxTok, &hj)
		if err != nil {
			return fiber.NewError(500, "Model for this key not found")
		}
		_ = json.Unmarshal([]byte(hj), &cfg.Headers)
		var r GenReq
		_ = c.BodyParser(&r)
		start := time.Now()
		outText, err := callLLM(cfg, r.Prompt)
		if err != nil {
			return fiber.NewError(502, err.Error())
		}
		lat := time.Since(start).Milliseconds()
		toks := (len(r.Prompt) + len(outText)) / 4
		_, _ = db.Exec(`INSERT INTO usage_logs (api_key_id, ts, tokens, model, latency_ms, endpoint) VALUES (?,?,?,?,?,?)`,
			ak.ID, nowUTC(), toks, cfg.Model, lat, "/llm/generate")
		return c.JSON(fiber.Map{"output": outText})
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	log.Println("KeyLLM server listening on :8080")
	log.Fatal(app.Listen(":8080"))
}

// --- LLM CALLER ---
func callLLM(cfg ModelCfg, prompt string) (string, error) {
	var outText string
	switch strings.ToLower(cfg.Backend) {
	case "ollama":
		body := map[string]interface{}{"model": cfg.Model, "prompt": prompt, "options": map[string]interface{}{"temperature": cfg.Temp}, "stream": false}
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.URL, "/")+"/api/generate", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		var j map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&j)
		if s, ok := j["response"].(string); ok {
			outText = s
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
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		var j struct {
			Choices []struct {
				Message struct{ Content string `json:"content"` } `json:"message"`
			} `json:"choices"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&j)
		if len(j.Choices) > 0 {
			outText = j.Choices[0].Message.Content
		}
	default:
		return "", fmt.Errorf("unsupported backend: %s", cfg.Backend)
	}
	return outText, nil
}

// --- OPENAPI SPEC ---
func mustOpenAPISpec() []byte {
	spec := map[string]interface{}{
		"openapi": "3.0.0",
		"info":    map[string]string{"title": "KeyLLM API", "version": "2.0.0", "description": "Secure gateway for local LLMs."},
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
				"responses": map[string]interface{}{"200": respObj(map[string]string{"token": "string"})},
			}},
			"/admin/models": map[string]interface{}{
				"get":  secured("List all model configurations", respArr(obj(map[string]string{"id": "integer", "name": "string", "backend": "string"}))),
				"post": secured("Create a new model configuration", respEmpty(), reqObj(map[string]string{"name": "string", "backend": "string", "url": "string", "model_name": "string"})),
			},
			"/admin/models/{id}": map[string]interface{}{
				"delete": secured("Delete a model configuration", respEmpty()),
			},
			"/admin/models/{id}/chat": map[string]interface{}{
				"post": secured("Test a model with a chat prompt", respObj(map[string]string{"output": "string"}), reqObj(map[string]string{"prompt": "string"})),
			},
			"/admin/keys": map[string]interface{}{
				"get": secured("List all API keys", respArr(obj(map[string]string{"id": "integer", "key": "string", "model_name": "string"}))),
				"post": secured("Create a new API key", respEmpty(), reqObj(map[string]string{"label": "string", "owner": "string", "model_id": "integer"})),
			},
			"/admin/keys/{id}": map[string]interface{}{
				"delete": secured("Delete an API key", respEmpty()),
			},
			"/llm/generate": map[string]interface{}{"post": map[string]interface{}{
				"summary":     "Generate text using a valid API key",
				"parameters":  []map[string]interface{}{{"name": "X-API-Key", "in": "header", "required": true, "schema": map[string]string{"type": "string"}}},
				"requestBody": reqObj(map[string]string{"prompt": "string"}),
				"responses":   map[string]interface{}{"200": respObj(map[string]string{"output": "string"})},
			}},
			"/health": map[string]interface{}{"get": map[string]interface{}{"summary": "Health check", "responses": map[string]interface{}{"200": respObj(map[string]string{"status": "string"})}}},
		},
	}
	b, _ := json.MarshalIndent(spec, "", "  ")
	return b
}
func secured(summary string, response interface{}, requestBody ...interface{}) map[string]interface{} {
	pathItem := map[string]interface{}{
		"summary":  summary,
		"security": []map[string]interface{}{{"BearerAuth": []string{}}},
		"responses": map[string]interface{}{
			"200": response,
			"401": map[string]interface{}{"description": "Unauthorized"},
		},
	}
	if len(requestBody) > 0 {
		pathItem["requestBody"] = requestBody[0]
	}
	return pathItem
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