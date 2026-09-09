// Package ratelimit provê limitadores de taxa: memória (padrão) ou Redis (opcional).
package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter decide se uma chave (token/IP/endpoint) pode prosseguir.
type Limiter interface {
	Allow(ctx context.Context, key string) bool
	Close() error
}

// Config de limite.
type Config struct {
	Enabled bool
	Limit   int           // requisições permitidas
	Window  time.Duration // janela
}

// Memory é um limitador em memória (token bucket simples) — usado quando Redis não está configurado.
type Memory struct {
	mu     sync.Mutex
	buckets map[string]*bucket
	limit  int
	window time.Duration
}

type bucket struct {
	count int
	reset time.Time
}

// NewMemory cria um limitador em memória.
func NewMemory(cfg Config) *Memory {
	if cfg.Limit <= 0 {
		cfg.Limit = 30
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Second
	}
	return &Memory{buckets: map[string]*bucket{}, limit: cfg.Limit, window: cfg.Window}
}

// Allow implementa Limiter.
func (m *Memory) Allow(_ context.Context, key string) bool {
	if !m.Enabled() {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	b, ok := m.buckets[key]
	if !ok || now.After(b.reset) {
		m.buckets[key] = &bucket{count: 1, reset: now.Add(m.window)}
		return true
	}
	if b.count >= m.limit {
		return false
	}
	b.count++
	return true
}

func (m *Memory) Enabled() bool { return true }

// Close implementa Limiter.
func (m *Memory) Close() error { return nil }

// Redis é um limitador que usa o backend Redis (Escale, multi-entrada).
type Redis struct {
	client *redis.Client
	limit  int
	window time.Duration
}

// NewRedis conecta e retorna um limitador Redis.
func NewRedis(host string, port int, password string, db int, cfg Config) (*Redis, error) {
	r := redis.NewClient(&redis.Options{Addr: hostport(host, port), Password: password, DB: db})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 30
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Second
	}
	return &Redis{client: r, limit: cfg.Limit, window: cfg.Window}, nil
}

// Allow implementa Limiter (INCR + EXPIRE; janela deslizante simples).
func (r *Redis) Allow(ctx context.Context, key string) bool {
	k := "nhooks:rl:" + key
	n, err := r.client.Incr(ctx, k).Result()
	if err != nil {
		return true // falha ao manter limite: libera por segurança
	}
	if n == 1 {
		r.client.Expire(ctx, k, r.window)
	}
	return n <= int64(r.limit)
}

// Close implementa Limiter.
func (r *Redis) Close() error { return r.client.Close() }

func hostport(host string, port int) string {
	if port <= 0 {
		port = 6379
	}
	return host + ":" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
