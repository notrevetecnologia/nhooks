// Package ai implementa um cliente compatível com o contrato Chat Completions da Notreve IA (e OpenAI).
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client é um cliente thin para /v1/chat/completions com autenticação Bearer.
type Client struct {
	key   string
	base  string
	model string
	app   string
	httpc *http.Client
}

// New cria um cliente. model='' usa o padrão.
func New(key, base, model, app string) *Client {
	c := &Client{key: key, base: strings.TrimRight(base, "/"), model: model, app: app}
	if c.model == "" {
		c.model = "notreve-v1-lite"
	}
	c.httpc = &http.Client{Timeout: 70 * time.Second}
	return c
}

// Enabled informa se há chave no servidor (AI_API_KEY).
func (c *Client) Enabled() bool { return c.key != "" }

// HasKey verifica a chave efetiva para uma chamada (per-call ou do servidor).
func (c *Client) HasKey(provided string) bool { return provided != "" || c.key != "" }

// Label é o nome do serviço exibido na UI.
func (c *Client) Label() string { return c.app }

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string             `json:"model"`
	Messages       []message          `json:"messages"`
	ResponseFormat *map[string]string `json:"response_format,omitempty"`
	Temperature    float64            `json:"temperature"`
	MaxTokens      int                `json:"max_tokens"`
	Stream         bool               `json:"stream"`
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// chat envia a requisição e devolve o conteúdo da resposta. A chave usada é a
// fornecida por chamada (keyOverride) quando não vazia, senão a do servidor.
func (c *Client) chat(ctx context.Context, system, user, model, keyOverride string) (string, string, int, error) {
	key := keyOverride
	if key == "" {
		key = c.key
	}
	if key == "" {
		return "", "", 0, errors.New("chave de IA nao configurada")
	}
	m := c.model
	if model != "" {
		m = model
	}
	payload := chatRequest{
		Model:          m,
		Messages:       []message{{Role: "system", Content: system}, {Role: "user", Content: user}},
		Temperature:    0.3,
		MaxTokens:      1200,
		Stream:         false,
		ResponseFormat: &map[string]string{"type": "json_object"},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := c.httpc.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", "", 0, fmt.Errorf("resposta invalida (%d): %s", resp.StatusCode, truncate(string(raw), 200))
	}
	if resp.StatusCode >= 400 || cr.Error != nil {
		msg := "erro desconhecido"
		if cr.Error != nil {
			msg = cr.Error.Message
		}
		return "", "", 0, fmt.Errorf("erro da IA (%d): %s", resp.StatusCode, msg)
	}
	if len(cr.Choices) == 0 {
		return "", "", 0, errors.New("a IA nao retornou choices")
	}
	return cr.Choices[0].Message.Content, cr.Model, cr.Usage.TotalTokens, nil
}

// Insight é o resultado estruturado da analise de um evento.
type Insight struct {
	Summary    string   `json:"summary"`
	Anomalies  []string `json:"anomalies"`
	Suggestion string   `json:"suggestion"`
	Status     string   `json:"status"`
	Model      string   `json:"model"`
	Tokens     int      `json:"tokens"`
}

// Insight analisa o JSON de um evento (method, uri, headers, body) e devolve resumo/anomalias.
// keyOverride, quando não vazio, usa a chave do cliente em vez da do servidor.
func (c *Client) Insight(ctx context.Context, eventJSON []byte, model, keyOverride string) (Insight, error) {
	system := "Você é um analista técnico de webhooks. A partir do JSON do evento recebido, retorne SEMPRE um objeto JSON válido com exatamente esta estrutura: {\"summary\":\"resumo em português do evento em 2 a 3 frases, citando método, origem e dado relevante do payload\",\"anomalies\":[\"lista de anomalias ou pontos de atenção; vazio se nenhum\"],\"suggestion\":\"orientação prática de 1 frase para quem testa essa integração\",\"status\":\"ok | warning\"}. Não invente dados ausentes no payload. Retorne apenas o JSON."
	content, respModel, tokens, err := c.chat(ctx, system, string(eventJSON), model, keyOverride)
	if err != nil {
		return Insight{}, err
	}
	var ins Insight
	if err := json.Unmarshal([]byte(content), &ins); err != nil {
		return Insight{}, fmt.Errorf("a IA nao retornou JSON valido: %w", err)
	}
	ins.Model = respModel
	ins.Tokens = tokens
	return ins, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
