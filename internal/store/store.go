// Package store implementa persistência pluggable: SQLite embutido (padrão) ou PostgreSQL.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres
	"github.com/notrevetecnologia/nhooks/internal/config"
	"github.com/notrevetecnologia/nhooks/internal/domain"
	"github.com/notrevetecnologia/nhooks/internal/security"

	_ "modernc.org/sqlite" // sqlite (pure go)
)

// Store encapsula o *sql.DB, o dialeto e a chave de criptografia de eventos.
type Store struct {
	db                *sql.DB
	dialect           string // "sqlite" | "postgres"
	key               string // chave de decriptografia (vazia = sem criptografia)
	encryptionEnabled bool
}

// Open abre o banco conforme DB_DRIVER (sqlite | postgres) e garante o schema.
func Open(cfg config.Config) (*Store, error) {
	driver, dialect := pickDriver(cfg.DBDriver)
	dsn := dsnFor(cfg, driver)
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(cfg.DBMaxOpenConns)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &Store{db: db, dialect: dialect, key: cfg.EventEncryptionKey, encryptionEnabled: cfg.EventEncryptionEnabled}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func pickDriver(d string) (driver, dialect string) {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "postgres", "postgresql", "pg", "pgx":
		return "pgx", "postgres"
	default:
		return "sqlite", "sqlite"
	}
}

func dsnFor(cfg config.Config, driver string) string {
	if driver == "pgx" {
		if cfg.DBDSN != "" {
			return cfg.DBDSN
		}
		return defaultPostgresDSN(cfg)
	}
	return "file:" + cfg.DBPath + "?_journal=WAL&_busy_timeout=5000"
}

func defaultPostgresDSN(cfg config.Config) string {
	ps := []string{
		"host=" + os.Getenv("DB_HOST"),
		"port=" + envOr("DB_PORT", "5432"),
		"dbname=" + envOr("DB_NAME", "nhooks"),
		"user=" + envOr("DB_USER", "nhooks"),
	}
	if pw := os.Getenv("DB_PASSWORD"); pw != "" {
		ps = append(ps, "password="+pw)
	}
	if cfg.DBSSLMode != "" {
		ps = append(ps, "sslmode="+cfg.DBSSLMode)
	}
	return strings.Join(ps, " ")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// rebind converte placeholders "?" em "$N" para PostgreSQL.
func (s *Store) rebind(q string) string {
	if s.dialect != "postgres" {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteByte(q[i])
		}
	}
	return b.String()
}

func (s *Store) exec(q string, args ...any) (sql.Result, error) {
	return s.db.Exec(s.rebind(q), args...)
}
func (s *Store) query(q string, args ...any) (*sql.Rows, error) {
	return s.db.Query(s.rebind(q), args...)
}
func (s *Store) queryRow(q string, args ...any) *sql.Row { return s.db.QueryRow(s.rebind(q), args...) }

func (s *Store) migrate() error {
	// DDL compatível entre SQLite e PostgreSQL (ids TEXT, tempos INTEGER/unix).
	if _, err := s.exec(schema); err != nil {
		return err
	}
	if s.dialect == "postgres" {
		_, err := s.exec(`ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS hmac_required INTEGER NOT NULL DEFAULT 0`)
		return err
	}
	rows, err := s.query(`PRAGMA table_info(endpoints)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "hmac_required" {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = s.exec(`ALTER TABLE endpoints ADD COLUMN hmac_required INTEGER NOT NULL DEFAULT 0`)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS admins (
  admin_key  TEXT PRIMARY KEY,
  created_at INTEGER,
  last_seen  INTEGER
);
CREATE TABLE IF NOT EXISTS endpoints (
  token        TEXT PRIMARY KEY,
  slug         TEXT UNIQUE,
  name         TEXT,
  admin_key    TEXT,
  share_key    TEXT,
  secret       TEXT,
  hmac_required INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER,
  last_event_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ep_admin ON endpoints(admin_key);
CREATE TABLE IF NOT EXISTS events (
  id            TEXT PRIMARY KEY,
  endpoint_token TEXT,
  method        TEXT,
  path          TEXT,
  ip            TEXT,
  content_type  TEXT,
  query         TEXT,
  post          TEXT,
  headers       TEXT,
  body          TEXT,
  body_json     TEXT,
  size          INTEGER,
  received_at   INTEGER,
  created_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ev_ep_at ON events(endpoint_token, received_at);
CREATE INDEX IF NOT EXISTS idx_ev_at ON events(received_at);
CREATE TABLE IF NOT EXISTS metas (
  k TEXT PRIMARY KEY,
  v TEXT
);
CREATE TABLE IF NOT EXISTS idempotency_keys (
  endpoint_token TEXT,
  idem_key       TEXT,
  created_at     INTEGER,
  PRIMARY KEY(endpoint_token, idem_key)
);
CREATE INDEX IF NOT EXISTS idx_idem_created ON idempotency_keys(created_at);
`

// ---------- criptografia ----------

func (s *Store) encryptOn() bool {
	return s.encryptionEnabled && s.key != "" && s.key != "change-this-secret-key"
}

// encode devolve (coluna_body, coluna_body_json). Com criptografia ativa, body+json
// vão juntos (separados por \x00) dentro de um único ciphertext.
func (s *Store) encode(body, bodyJSON []byte) (string, string) {
	if s.encryptOn() && (len(body) > 0 || len(bodyJSON) > 0) {
		payload := append(body, append([]byte{0}, bodyJSON...)...)
		if ct, err := security.EncryptAES([]byte(s.key), payload); err == nil {
			return ct, ""
		}
	}
	return string(body), string(bodyJSON)
}

func (s *Store) decodeRow(bodyCol, jsonCol string) (string, []byte) {
	if s.key != "" && s.key != "change-this-secret-key" && bodyCol != "" {
		if plain, err := security.DecryptAES([]byte(s.key), bodyCol); err == nil {
			if i := indexByte(plain, 0); i >= 0 {
				return string(plain[:i]), append([]byte(nil), plain[i+1:]...)
			}
			return string(plain), nil
		}
	}
	return bodyCol, []byte(jsonCol)
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// ---------- Admin ----------

func (s *Store) EnsureAdmin(adminKey string) error {
	now := time.Now().Unix()
	_, err := s.exec(`INSERT INTO admins(admin_key, created_at, last_seen) VALUES(?,?,?)
		ON CONFLICT(admin_key) DO UPDATE SET last_seen=excluded.last_seen`, adminKey, now, now)
	return err
}

// EnsureAdminWithDefault cria o cliente e, se necessário, seu primeiro endpoint
// na mesma transação para evitar duplicação em boots concorrentes.
func (s *Store) EnsureAdminWithDefault(adminKey string, ep *domain.Endpoint) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.Exec(s.rebind(`INSERT INTO admins(admin_key,created_at,last_seen) VALUES(?,?,?) ON CONFLICT(admin_key) DO UPDATE SET last_seen=excluded.last_seen`), adminKey, now, now); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(s.rebind(`SELECT COUNT(1) FROM endpoints WHERE admin_key=?`), adminKey).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := tx.Exec(s.rebind(`INSERT INTO endpoints(token,slug,name,admin_key,share_key,secret,hmac_required,created_at,last_event_at) VALUES(?,?,?,?,?,?,?,?,?)`),
			ep.Token, ep.Slug, ep.Name, adminKey, ep.ShareKey, ep.Secret, boolInt(ep.HMACRequired), ep.CreatedAt.Unix(), ep.LastEventAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AdminExists(adminKey string) bool {
	var n int
	_ = s.queryRow(`SELECT COUNT(1) FROM admins WHERE admin_key=?`, adminKey).Scan(&n)
	return n > 0
}

// ---------- Endpoints ----------

func (s *Store) CreateEndpoint(ep *domain.Endpoint) error {
	_, err := s.exec(`INSERT INTO endpoints(token,slug,name,admin_key,share_key,secret,hmac_required,created_at,last_event_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, ep.Token, ep.Slug, ep.Name, ep.AdminKey, ep.ShareKey, ep.Secret, boolInt(ep.HMACRequired), ep.CreatedAt.Unix(), ep.LastEventAt)
	return err
}

func scanEndpoint(row *sql.Row) (*domain.Endpoint, error) {
	var e domain.Endpoint
	var created int64
	var hmacRequired int
	if err := row.Scan(&e.Token, &e.Slug, &e.Name, &e.AdminKey, &e.ShareKey, &e.Secret, &hmacRequired, &created, &e.LastEventAt); err != nil {
		return nil, err
	}
	e.CreatedAt = time.Unix(created, 0)
	e.HMACRequired = hmacRequired != 0
	return &e, nil
}

func (s *Store) EndpointByToken(token string) (*domain.Endpoint, error) {
	if token == "" {
		return nil, errors.New("token vazio")
	}
	return scanEndpoint(s.queryRow(`SELECT token,slug,name,admin_key,share_key,secret,hmac_required,created_at,last_event_at FROM endpoints WHERE token=?`, token))
}

func (s *Store) EndpointBySlug(slug string) (*domain.Endpoint, error) {
	if slug == "" {
		return nil, errors.New("slug vazio")
	}
	return scanEndpoint(s.queryRow(`SELECT token,slug,name,admin_key,share_key,secret,hmac_required,created_at,last_event_at FROM endpoints WHERE slug=?`, slug))
}

func (s *Store) EndpointsByAdmin(adminKey string) ([]domain.Endpoint, error) {
	rows, err := s.query(`SELECT token,slug,name,admin_key,share_key,secret,hmac_required,created_at,last_event_at FROM endpoints WHERE admin_key=? ORDER BY created_at DESC`, adminKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Endpoint
	for rows.Next() {
		var e domain.Endpoint
		var created int64
		var hmacRequired int
		if err := rows.Scan(&e.Token, &e.Slug, &e.Name, &e.AdminKey, &e.ShareKey, &e.Secret, &hmacRequired, &created, &e.LastEventAt); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(created, 0)
		e.HMACRequired = hmacRequired != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) EndpointBelongsTo(adminKey, token string) bool {
	var n int
	_ = s.queryRow(`SELECT COUNT(1) FROM endpoints WHERE admin_key=? AND token=?`, adminKey, token).Scan(&n)
	return n > 0
}

func (s *Store) TouchEndpoint(token string) {
	_, _ = s.exec(`UPDATE endpoints SET last_event_at=? WHERE token=?`, time.Now().Unix(), token)
}

func (s *Store) DeleteEndpoint(adminKey, token string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(s.rebind(`DELETE FROM events WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=? AND token=?)`), adminKey, token); err != nil {
		return false, err
	}
	if _, err := tx.Exec(s.rebind(`DELETE FROM idempotency_keys WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=? AND token=?)`), adminKey, token); err != nil {
		return false, err
	}
	res, err := tx.Exec(s.rebind(`DELETE FROM endpoints WHERE admin_key=? AND token=?`), adminKey, token)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) SharedEndpoint(shareKey string) (*domain.Endpoint, error) {
	if shareKey == "" {
		return nil, errors.New("share key vazia")
	}
	return scanEndpoint(s.queryRow(`SELECT token,slug,name,admin_key,share_key,secret,hmac_required,created_at,last_event_at FROM endpoints WHERE share_key=? AND share_key<>''`, shareKey))
}

// ---------- Events ----------

func (s *Store) CreateEvent(ev *domain.Event) error {
	encBody, encJSON := s.encode([]byte(ev.Body), ev.BodyJSON)
	_, err := s.exec(`INSERT INTO events(id,endpoint_token,method,path,ip,content_type,query,post,headers,body,body_json,size,received_at,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.ID, ev.EndpointToken, ev.Method, ev.Path, ev.IP, ev.ContentType,
		mustJSON(ev.Query), mustJSON(ev.Post), mustJSON(ev.Headers),
		encBody, encJSON, ev.Size, ev.ReceivedAt, time.Now().Unix())
	return err
}

// CreateEventOnce persiste o evento e a chave idempotente na mesma transação.
// Retorna false quando a chave já foi usada para o endpoint.
func (s *Store) CreateEventOnce(ev *domain.Event, idemKey string) (bool, error) {
	created, reason, err := s.CreateEventWithinLimits(ev, idemKey, 0, 0)
	return created && reason == "", err
}

// CreateEventWithinLimits serializa idempotência, quotas e persistência.
func (s *Store) CreateEventWithinLimits(ev *domain.Event, idemKey string, maxEvents int, maxStorage int64) (bool, string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, "", err
	}
	defer tx.Rollback()
	if s.dialect == "postgres" {
		var token string
		if err := tx.QueryRow(s.rebind(`SELECT token FROM endpoints WHERE token=? FOR UPDATE`), ev.EndpointToken).Scan(&token); err != nil {
			return false, "", err
		}
	} else if _, err := tx.Exec(s.rebind(`UPDATE endpoints SET last_event_at=last_event_at WHERE token=?`), ev.EndpointToken); err != nil {
		return false, "", err
	}
	if idemKey != "" {
		res, err := tx.Exec(s.rebind(`INSERT INTO idempotency_keys(endpoint_token,idem_key,created_at) VALUES(?,?,?) ON CONFLICT(endpoint_token,idem_key) DO NOTHING`), ev.EndpointToken, idemKey, time.Now().Unix())
		if err != nil {
			return false, "", err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return false, "duplicate", nil
		}
	}
	if maxEvents > 0 {
		var count int
		if err := tx.QueryRow(s.rebind(`SELECT COUNT(1) FROM events WHERE endpoint_token=?`), ev.EndpointToken).Scan(&count); err != nil {
			return false, "", err
		}
		if count >= maxEvents {
			return false, "event_limit", nil
		}
	}
	if maxStorage > 0 {
		var used int64
		if err := tx.QueryRow(s.rebind(`SELECT COALESCE(SUM(size),0) FROM events WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=(SELECT admin_key FROM endpoints WHERE token=?))`), ev.EndpointToken).Scan(&used); err != nil {
			return false, "", err
		}
		if used+int64(ev.Size) > maxStorage {
			return false, "storage_limit", nil
		}
	}
	encBody, encJSON := s.encode([]byte(ev.Body), ev.BodyJSON)
	_, err = tx.Exec(s.rebind(`INSERT INTO events(id,endpoint_token,method,path,ip,content_type,query,post,headers,body,body_json,size,received_at,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), ev.ID, ev.EndpointToken, ev.Method, ev.Path, ev.IP, ev.ContentType,
		mustJSON(ev.Query), mustJSON(ev.Post), mustJSON(ev.Headers), encBody, encJSON, ev.Size, ev.ReceivedAt, time.Now().Unix())
	if err != nil {
		return false, "", err
	}
	if err := tx.Commit(); err != nil {
		return false, "", err
	}
	return true, "", nil
}

func mustJSON(m any) string {
	if m == nil {
		return ""
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) EventByID(id string) (*domain.Event, error) {
	row := s.queryRow(`SELECT id,endpoint_token,method,path,ip,content_type,query,post,headers,body,body_json,size,received_at FROM events WHERE id=?`, id)
	return s.scanEvent(row)
}

func (s *Store) scanEvent(row *sql.Row) (*domain.Event, error) {
	var e domain.Event
	var query, post, headers, body, bodyJSON string
	if err := row.Scan(&e.ID, &e.EndpointToken, &e.Method, &e.Path, &e.IP, &e.ContentType, &query, &post, &headers, &body, &bodyJSON, &e.Size, &e.ReceivedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(query), &e.Query)
	_ = json.Unmarshal([]byte(post), &e.Post)
	_ = json.Unmarshal([]byte(headers), &e.Headers)
	rawBody, rawJSON := s.decodeRow(body, bodyJSON)
	e.Body = rawBody
	e.BodyJSON = append([]byte(nil), rawJSON...)
	if e.Size == 0 {
		e.Size = len(rawBody)
	}
	return &e, nil
}

// EventRow é um evento na listagem do painel (com nome/slug do endpoint).
type EventRow struct {
	domain.Event
	EndpointName string `json:"endpoint_name"`
	EndpointSlug string `json:"endpoint_slug"`
}

// EventsForAdmin lista eventos paginados por cursor (received_at desc).
func (s *Store) EventsForAdmin(adminKey, token string, limit int, before int64) ([]EventRow, error) {
	return s.EventsForAdminFiltered(adminKey, EventFilter{Token: token, Limit: limit})
}

// EventFilter reúne filtros e paginação das listagens do painel.
type EventFilter struct {
	Token, Query, Method, Order string
	Limit, Offset               int
}

func (s *Store) EventsForAdminFiltered(adminKey string, f EventFilter) ([]EventRow, error) {
	q := `SELECT e.id,e.endpoint_token,e.method,e.path,e.ip,e.content_type,e.query,e.post,e.headers,e.body,e.body_json,e.size,e.received_at,ep.name,ep.slug
	      FROM events e JOIN endpoints ep ON ep.token=e.endpoint_token
	      WHERE ep.admin_key=?`
	args := []any{adminKey}
	if f.Token != "" {
		q += ` AND e.endpoint_token=?`
		args = append(args, f.Token)
	}
	q, args = appendEventFilters(q, args, f)
	q += eventOrder(f.Order) + ` LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)
	return s.eventRows(q, args...)
}

func (s *Store) CountEventsForAdmin(adminKey string, f EventFilter) (int, error) {
	q := `SELECT COUNT(1) FROM events e JOIN endpoints ep ON ep.token=e.endpoint_token WHERE ep.admin_key=?`
	args := []any{adminKey}
	if f.Token != "" {
		q += ` AND e.endpoint_token=?`
		args = append(args, f.Token)
	}
	q, args = appendEventFilters(q, args, f)
	var n int
	err := s.queryRow(q, args...).Scan(&n)
	return n, err
}

func appendEventFilters(q string, args []any, f EventFilter) (string, []any) {
	if f.Method != "" {
		q += ` AND e.method=?`
		args = append(args, strings.ToUpper(f.Method))
	}
	if search := strings.TrimSpace(f.Query); search != "" {
		like := "%" + strings.ToLower(search) + "%"
		q += ` AND (LOWER(e.id) LIKE ? OR LOWER(e.path) LIKE ? OR LOWER(e.ip) LIKE ? OR LOWER(e.content_type) LIKE ? OR LOWER(ep.name) LIKE ? OR LOWER(e.query) LIKE ? OR LOWER(e.headers) LIKE ? OR LOWER(e.body) LIKE ?)`
		for range 8 {
			args = append(args, like)
		}
	}
	return q, args
}

func eventOrder(order string) string {
	switch order {
	case "oldest":
		return ` ORDER BY e.received_at ASC, e.id ASC`
	case "method":
		return ` ORDER BY e.method ASC, e.received_at DESC, e.id DESC`
	default:
		return ` ORDER BY e.received_at DESC, e.id DESC`
	}
}

func (s *Store) eventRows(q string, args ...any) ([]EventRow, error) {
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventRow
	for rows.Next() {
		var er EventRow
		var query, post, headers, body, bodyJSON string
		if err := rows.Scan(&er.ID, &er.EndpointToken, &er.Method, &er.Path, &er.IP, &er.ContentType, &query, &post, &headers, &body, &bodyJSON, &er.Size, &er.ReceivedAt, &er.EndpointName, &er.EndpointSlug); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(query), &er.Query)
		_ = json.Unmarshal([]byte(post), &er.Post)
		_ = json.Unmarshal([]byte(headers), &er.Headers)
		rawBody, rawJSON := s.decodeRow(body, bodyJSON)
		er.Body = rawBody
		er.BodyJSON = append([]byte(nil), rawJSON...)
		out = append(out, er)
	}
	return out, rows.Err()
}

func (s *Store) EventByIDForAdmin(adminKey, eventID string) (*domain.Event, error) {
	ev, err := s.EventByID(eventID)
	if err != nil {
		return nil, err
	}
	if !s.EndpointBelongsTo(adminKey, ev.EndpointToken) {
		return nil, errors.New("evento nao encontrado")
	}
	return ev, nil
}

func (s *Store) EventByIDForShare(shareKey, eventID string) (*domain.Event, error) {
	shared, err := s.SharedEndpoint(shareKey)
	if err != nil {
		return nil, err
	}
	ev, err := s.EventByID(eventID)
	if err != nil {
		return nil, err
	}
	if ev.EndpointToken != shared.Token {
		return nil, errors.New("evento nao encontrado")
	}
	return ev, nil
}

func (s *Store) DeleteEventForAdmin(adminKey, eventID string) (bool, error) {
	if _, err := s.EventByIDForAdmin(adminKey, eventID); err != nil {
		return false, err
	}
	res, err := s.exec(`DELETE FROM events WHERE id=?`, eventID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) ClearEventsForAdmin(adminKey, token string) (int64, error) {
	if token != "" {
		tx, err := s.db.Begin()
		if err != nil {
			return 0, err
		}
		defer tx.Rollback()
		res, err := tx.Exec(s.rebind(`DELETE FROM events WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=? AND token=?)`), adminKey, token)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(s.rebind(`DELETE FROM idempotency_keys WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=? AND token=?)`), adminKey, token); err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return n, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(s.rebind(`DELETE FROM events WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=?)`), adminKey)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(s.rebind(`DELETE FROM idempotency_keys WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=?)`), adminKey); err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) Quota(adminKey string) (events int64, bytes int64) {
	_ = s.queryRow(`SELECT COUNT(1), COALESCE(SUM(size),0) FROM events WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=?)`, adminKey).Scan(&events, &bytes)
	return events, bytes
}

func (s *Store) EventCountForEndpoint(token string) int {
	var n int
	_ = s.queryRow(`SELECT COUNT(1) FROM events WHERE endpoint_token=?`, token).Scan(&n)
	return n
}

func (s *Store) RetentionRemove(hours int) (int64, error) {
	if hours <= 0 {
		return 0, nil
	}
	cut := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	res, err := s.exec(`DELETE FROM events WHERE received_at < ?`, cut)
	if err != nil {
		return 0, err
	}
	_, _ = s.exec(`DELETE FROM idempotency_keys WHERE created_at < ?`, cut)
	return res.RowsAffected()
}

func (s *Store) MetaGet(k string) string {
	var v string
	_ = s.queryRow(`SELECT v FROM metas WHERE k=?`, k).Scan(&v)
	return v
}
func (s *Store) MetaSet(k, v string) error {
	_, err := s.exec(`INSERT INTO metas(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// AdminStats retorna métricas para o painel /admin.
func (s *Store) AdminStats() map[string]any {
	var endpoints, events int
	var bytes int64
	_ = s.queryRow(`SELECT COUNT(1) FROM endpoints`).Scan(&endpoints)
	_ = s.queryRow(`SELECT COUNT(1), COALESCE(SUM(size),0) FROM events`).Scan(&events, &bytes)
	return map[string]any{
		"endpoints":     endpoints,
		"events":        events,
		"storage_bytes": bytes,
		"now":           time.Now().Format("02/01/2006 15:04:05"),
	}
}

// EndpointInfo agrega um endpoint com contagem de eventos (para o painel admin).
type EndpointInfo struct {
	domain.Endpoint
	EventsCount int
}

// AdminInfo agrega um cliente (admin_key) com métricas.
type AdminInfo struct {
	AdminKey  string
	Created   int64
	LastSeen  int64
	Endpoints int
	Events    int64
}

// AllEndpoints lista todos os endpoints (admin, sem filtro de dono).
func (s *Store) AllEndpoints() ([]EndpointInfo, error) {
	rows, err := s.query(`SELECT e.token,e.slug,e.name,e.admin_key,e.share_key,e.secret,e.hmac_required,e.created_at,e.last_event_at,
		(SELECT COUNT(1) FROM events ev WHERE ev.endpoint_token=e.token) FROM endpoints e ORDER BY e.last_event_at DESC, e.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndpointInfo
	for rows.Next() {
		var ei EndpointInfo
		var created int64
		var hmacRequired int
		if err := rows.Scan(&ei.Token, &ei.Slug, &ei.Name, &ei.AdminKey, &ei.ShareKey, &ei.Secret, &hmacRequired, &created, &ei.LastEventAt, &ei.EventsCount); err != nil {
			return nil, err
		}
		ei.CreatedAt = time.Unix(created, 0)
		ei.HMACRequired = hmacRequired != 0
		out = append(out, ei)
	}
	return out, rows.Err()
}

// EventsForShare lista eventos do endpoint compartilhado (leitura).
func (s *Store) EventsForShare(shareKey string, limit int, before int64) ([]EventRow, error) {
	return s.EventsForShareFiltered(shareKey, EventFilter{Limit: limit})
}

func (s *Store) EventsForShareFiltered(shareKey string, f EventFilter) ([]EventRow, error) {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	q := `SELECT e.id,e.endpoint_token,e.method,e.path,e.ip,e.content_type,e.query,e.post,e.headers,e.body,e.body_json,e.size,e.received_at,ep.name,ep.slug
	      FROM events e JOIN endpoints ep ON ep.token=e.endpoint_token
	      WHERE ep.share_key=? AND ep.share_key<>''`
	args := []any{shareKey}
	q, args = appendEventFilters(q, args, f)
	q += eventOrder(f.Order) + ` LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEventRows(rows, s)
}

func (s *Store) CountEventsForShare(shareKey string, f EventFilter) (int, error) {
	q := `SELECT COUNT(1) FROM events e JOIN endpoints ep ON ep.token=e.endpoint_token WHERE ep.share_key=? AND ep.share_key<>''`
	args := []any{shareKey}
	q, args = appendEventFilters(q, args, f)
	var n int
	err := s.queryRow(q, args...).Scan(&n)
	return n, err
}

func scanEventRows(rows *sql.Rows, s *Store) ([]EventRow, error) {
	var out []EventRow
	for rows.Next() {
		var er EventRow
		var query, post, headers, body, bodyJSON string
		if err := rows.Scan(&er.ID, &er.EndpointToken, &er.Method, &er.Path, &er.IP, &er.ContentType, &query, &post, &headers, &body, &bodyJSON, &er.Size, &er.ReceivedAt, &er.EndpointName, &er.EndpointSlug); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(query), &er.Query)
		_ = json.Unmarshal([]byte(post), &er.Post)
		_ = json.Unmarshal([]byte(headers), &er.Headers)
		rawBody, rawJSON := s.decodeRow(body, bodyJSON)
		er.Body = rawBody
		er.BodyJSON = append([]byte(nil), rawJSON...)
		out = append(out, er)
	}
	return out, rows.Err()
}

// AllEvents lista eventos de todos os endpoints (admin, sem filtro de dono).
func (s *Store) AllEvents(limit int) ([]EventRow, error) {
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT e.id,e.endpoint_token,e.method,e.path,e.ip,e.content_type,e.query,e.post,e.headers,e.body,e.body_json,e.size,e.received_at,ep.name,ep.slug
	      FROM events e JOIN endpoints ep ON ep.token=e.endpoint_token
	      ORDER BY e.received_at DESC, e.id DESC LIMIT ?`
	rows, err := s.query(q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventRow
	for rows.Next() {
		var er EventRow
		var query, post, headers, body, bodyJSON string
		if err := rows.Scan(&er.ID, &er.EndpointToken, &er.Method, &er.Path, &er.IP, &er.ContentType, &query, &post, &headers, &body, &bodyJSON, &er.Size, &er.ReceivedAt, &er.EndpointName, &er.EndpointSlug); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(query), &er.Query)
		_ = json.Unmarshal([]byte(post), &er.Post)
		_ = json.Unmarshal([]byte(headers), &er.Headers)
		rawBody, rawJSON := s.decodeRow(body, bodyJSON)
		er.Body = rawBody
		er.BodyJSON = append([]byte(nil), rawJSON...)
		out = append(out, er)
	}
	return out, rows.Err()
}

// AllAdmins lista os clientes (admins) com contagem de endpoints/eventos.
func (s *Store) AllAdmins() ([]AdminInfo, error) {
	rows, err := s.query(`SELECT a.admin_key, a.created_at, a.last_seen,
		(SELECT COUNT(1) FROM endpoints e WHERE e.admin_key=a.admin_key),
		(SELECT COUNT(1) FROM events ev WHERE ev.endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=a.admin_key))
		FROM admins a ORDER BY a.last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminInfo
	for rows.Next() {
		var ai AdminInfo
		if err := rows.Scan(&ai.AdminKey, &ai.Created, &ai.LastSeen, &ai.Endpoints, &ai.Events); err != nil {
			return nil, err
		}
		out = append(out, ai)
	}
	return out, rows.Err()
}

// DeleteAdmin remove o cliente e todos os endpoints/eventos dele.
func (s *Store) DeleteAdmin(adminKey string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(s.rebind(`DELETE FROM events WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=?)`), adminKey)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.Exec(s.rebind(`DELETE FROM idempotency_keys WHERE endpoint_token IN (SELECT token FROM endpoints WHERE admin_key=?)`), adminKey); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(s.rebind(`DELETE FROM endpoints WHERE admin_key=?`), adminKey); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(s.rebind(`DELETE FROM admins WHERE admin_key=?`), adminKey); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// DeleteEventAdmin remove um evento sem escopo de cliente, para o painel do sistema.
func (s *Store) DeleteEventAdmin(eventID string) (bool, error) {
	res, err := s.exec(`DELETE FROM events WHERE id=?`, eventID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) DeleteEndpointAdmin(token string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(s.rebind(`DELETE FROM events WHERE endpoint_token=?`), token); err != nil {
		return false, err
	}
	if _, err := tx.Exec(s.rebind(`DELETE FROM idempotency_keys WHERE endpoint_token=?`), token); err != nil {
		return false, err
	}
	res, err := tx.Exec(s.rebind(`DELETE FROM endpoints WHERE token=?`), token)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// GlobalClearEvents apaga todos os eventos.
func (s *Store) GlobalClearEvents() (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM events`)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM idempotency_keys`); err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// Close fecha o banco.
func (s *Store) Close() error { return s.db.Close() }
