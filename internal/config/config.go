// Package config carrega a configuração do NHooks a partir de .env/ambiente.
package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Config reúne todas as opções de runtime, com defaults sensatos.
type Config struct {
	Name               string // nome da marca (BRAND_NAME)
	Title              string // título da página (APP_TITLE)
	Description        string
	Eyebrow            string
	LogoURL            string
	FaviconURL         string
	CompanyURL         string
	Theme              string // light | dark | auto
	LogoHeight         string
	Primary, Secondary string // cores
	Dim                string

	IngestRoute string // rota amigável predeterminada (default "hook") -> /hook/{slug}
	LegacyRoute string // compat /in?token= (default "in")
	ToolPath    string // default "dashboard"

	ListenAddr string
	PublicURL  string // URL pública para montar links

	RedisEnabled  bool
	RedisRequired bool
	RedisHost     string
	RedisPort     int
	RedisPassword string
	RedisDB       int

	AMQPEnabled bool
	AMQPURL     string
	AMQPQueue   string // fila padrão para processamento assíncrono

	AIEnabled bool
	AIKey     string
	AIModel   string
	AIBaseURL string
	AIKeysURL string
	AIAppName string

	DBPath                 string // arquivo SQLite
	DBDriver               string // sqlite (padrão) | postgres
	DBDSN                  string // DSN postgres (se vazio, monta de DB_*)
	DBSSLMode              string // postgres sslmode (default "")
	DBMaxOpenConns         int
	RetentionHours         int
	StorageLimitEnabled    bool
	StorageLimitBytes      int64
	EventsLimitEnabled     bool
	EventsLimit            int
	EventEncryptionEnabled bool
	EventEncryptionKey     string

	SystemAdminKey string // chave do painel /admin (vazio = desativado)

	PollingMS            int
	DashboardEventsLimit int
	SoundDefault         bool
	AutoscrollDefault    bool
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// parseSize converte "100MB", "1GB", "0", "unlimited" em bytes.
func parseSize(v string, def int64) int64 {
	v = strings.TrimSpace(strings.ToUpper(v))
	if v == "" {
		return def
	}
	mult := map[string]int64{"B": 1, "K": 1 << 10, "KB": 1 << 10, "M": 1 << 20, "MB": 1 << 20, "G": 1 << 30, "GB": 1 << 30, "T": 1 << 40, "TB": 1 << 40}
	for suf, m := range mult {
		if strings.HasSuffix(v, suf) {
			num := strings.TrimSpace(strings.TrimSuffix(v, suf))
			if f, err := strconv.ParseFloat(num, 64); err == nil {
				return int64(f * float64(m))
			}
		}
	}
	if strings.TrimSpace(v) == "0" || strings.Contains(strings.TrimSpace(v), "ILIMIT") || strings.Contains(strings.TrimSpace(v), "UNLIMIT") {
		return 0
	}
	return def
}

// Load lê .env (se existir) e mescla com as variáveis de ambiente, aplicando defaults.
func Load(path string) Config {
	readEnvFile(path)
	return Config{
		Name:        env("BRAND_NAME", env("APP_NAME", "NHooks")),
		Title:       env("APP_TITLE", env("BRAND_NAME", "NHooks")),
		Description: env("APP_DESCRIPTION", "Gere URLs amigáveis para receber e testar eventos de webhook em tempo real."),
		Eyebrow:     env("APP_EYEBROW", "Ambiente próprio de testes"),
		LogoURL:     env("BRAND_LOGO_URL", ""),
		FaviconURL:  env("BRAND_FAVICON_URL", ""),
		CompanyURL:  env("COMPANY_URL", "https://notreve.com.br"),
		Theme:       env("APP_THEME", "dark"),
		LogoHeight:  env("APP_LOGO_HEIGHT", "56px"),
		Primary:     env("BRAND_COLOR", "#12948e"),
		Secondary:   env("BRAND_COLOR_DARK", "#0d7a75"),
		Dim:         env("BRAND_COLOR_DIM", "#6dcfc9"),

		IngestRoute: safeIngestRoute(env("APP_INGEST_ROUTE", "hook")),
		LegacyRoute: strings.Trim(env("APP_INGEST_ROUTE_LEGACY", "in"), "/"),
		ToolPath:    strings.Trim(env("TOOL_PATH", "dashboard"), "/"),

		ListenAddr: env("LISTEN_ADDR", ":8080"),
		PublicURL:  strings.TrimRight(env("PUBLIC_URL", "http://localhost:8080"), "/"),

		RedisEnabled:  envBool("REDIS_ENABLED", false),
		RedisRequired: envBool("REDIS_REQUIRED", false),
		RedisHost:     env("REDIS_HOST", "127.0.0.1"),
		RedisPort:     envInt("REDIS_PORT", 6379),
		RedisPassword: env("REDIS_PASSWORD", ""),
		RedisDB:       envInt("REDIS_DB", 0),

		AMQPEnabled: envBool("AMQP_ENABLED", false),
		AMQPURL:     env("AMQP_URL", ""),
		AMQPQueue:   env("AMQP_QUEUE", "nhooks_async"),

		AIEnabled: envBool("AI_ENABLED", true),
		AIKey:     env("AI_API_KEY", ""),
		AIModel:   env("AI_MODEL", "notreve-v1-lite"),
		AIBaseURL: strings.TrimRight(env("AI_BASE_URL", "https://api.ia.notreve.com.br"), "/"),
		AIKeysURL: env("AI_KEYS_URL", "https://ia.notreve.com.br"),
		AIAppName: env("AI_APP_NAME", "IA"),

		DBPath:                 env("DB_PATH", "nhooks.db"),
		DBDriver:               env("DB_DRIVER", "sqlite"),
		DBDSN:                  env("DB_DSN", ""),
		DBSSLMode:              env("DB_SSLMODE", ""),
		DBMaxOpenConns:         envInt("DB_MAX_OPEN_CONNS", 1),
		RetentionHours:         envInt("EVENT_RETENTION_HOURS", 24),
		StorageLimitEnabled:    envBool("USER_STORAGE_LIMIT_ENABLED", true),
		StorageLimitBytes:      parseSize(env("USER_STORAGE_LIMIT", "100MB"), 100<<20),
		EventsLimitEnabled:     envBool("USER_EVENTS_LIMIT_ENABLED", true),
		EventsLimit:            envInt("USER_EVENTS_LIMIT", 10000),
		EventEncryptionEnabled: envBool("EVENT_ENCRYPTION_ENABLED", true),
		EventEncryptionKey:     env("EVENT_ENCRYPTION_KEY", ""),

		SystemAdminKey: env("SYSTEM_ADMIN_KEY", ""),

		PollingMS:            envInt("APP_POLLING_MS", 3000),
		DashboardEventsLimit: envInt("DASHBOARD_EVENTS_LIMIT", 200),
		SoundDefault:         envBool("SOUND_ENABLED_DEFAULT", false),
		AutoscrollDefault:    envBool("AUTOSCROLL_ENABLED_DEFAULT", true),
	}
}

func safeIngestRoute(v string) string {
	v = strings.Trim(strings.TrimSpace(v), "/")
	switch v {
	case "", "api", "admin", "health", "dash", "share", "static", "in":
		return "hook"
	default:
		return v
	}
}

// readEnvFile carrega um .env simples (linhas CHAVE=valor, # comentários). Não sobrescreve variáveis já definidas.
func readEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = parseEnvValue(val)
		if key == "" {
			continue
		}
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}

func parseEnvValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') {
		if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
			return v[1 : end+1]
		}
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return strings.Trim(v, `"'`)
}

// AIConfigured informa se a IA está pronta para uso (habilitada e com chave).
func (c Config) AIConfigured() bool {
	return c.AIEnabled && c.AIKey != ""
}
