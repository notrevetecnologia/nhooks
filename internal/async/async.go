// Package async provê um worker opcional via RabbitMQ (AMQP) para processamento em background.
// Quando AMQP_ENABLED=false, todas as funções viram no-op e nada bloqueia.
package async

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Job é uma tarefa enfileirada.
type Job struct {
	Kind  string          `json:"kind"` // "insight" | "cleanup" | "export"
	Event string          `json:"event_id"`
	Admin string          `json:"admin_key"`
	Token string          `json:"endpoint_token"`
	Model string          `json:"model"`
	RunAt time.Time       `json:"run_at"`
	Data  json.RawMessage `json:"data"`
}

// Worker publica/consome Jobs em uma fila AMQP. Sem conexão, é no-op.
type Worker struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	queue   string
	enabled bool
	mu      sync.Mutex
}

// New conecta (se habilitado) e garante a fila.
func New(url, queue string, enabled bool) (*Worker, error) {
	if !enabled || url == "" {
		return &Worker{enabled: false, queue: queue}, nil
	}
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if queue == "" {
		queue = "nhooks_async"
	}
	if _, err := ch.QueueDeclare(queue, true, false, false, false, nil); err != nil {
		ch.Close()
		conn.Close()
		return nil, err
	}
	return &Worker{conn: conn, channel: ch, queue: queue, enabled: true}, nil
}

// Enabled informa se o worker AMQP está ativo.
func (w *Worker) Enabled() bool { return w != nil && w.enabled }

// Publish enfileira um job (no-op se desativado).
func (w *Worker) Publish(ctx context.Context, j Job) error {
	if !w.Enabled() {
		return nil
	}
	b, _ := json.Marshal(j)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.channel.PublishWithContext(ctx, "", w.queue, false, false,
		amqp.Publishing{ContentType: "application/json", Body: b, DeliveryMode: amqp.Persistent})
}

// Consume roda um handler para cada mensagem, com reconexão simples. Chamado em goroutine.
func (w *Worker) Consume(ctx context.Context, fn func(Job) error) {
	if !w.Enabled() {
		return
	}
	deliveries, err := w.channel.Consume(w.queue, "", true, false, false, false, nil)
	if err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case d, ok := <-deliveries:
			if !ok {
				return
			}
			var j Job
			if err := json.Unmarshal(d.Body, &j); err == nil {
				_ = fn(j)
			}
		}
	}
}

// Close fecha o canal/conexão.
func (w *Worker) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.channel != nil {
		w.channel.Close()
	}
	if w.conn != nil {
		w.conn.Close()
	}
	return nil
}
