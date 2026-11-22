package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct{ LLDAPURL, Username, Password, Issuer, Audience, JWKSURL, Listen, AllowedClients string }
type App struct {
	cfg        Config
	http       *http.Client
	mu         sync.Mutex
	token      string
	tokenUntil time.Time
	keysMu     sync.Mutex
	keys       map[string]*rsa.PublicKey
	keysUntil  time.Time
}
type gqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func secret(k string) string {
	if f := os.Getenv(k + "_FILE"); f != "" {
		b, e := os.ReadFile(f)
		if e != nil {
			panic(e)
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv(k)
}
func main() {
	cfg := Config{LLDAPURL: env("LLDAP_URL", "http://lldap:17170"), Username: env("LLDAP_USERNAME", "admin"), Password: secret("LLDAP_PASSWORD"), Issuer: os.Getenv("OIDC_ISSUER"), Audience: os.Getenv("OIDC_AUDIENCE"), JWKSURL: os.Getenv("OIDC_JWKS_URL"), Listen: env("LISTEN_ADDR", ":8080"), AllowedClients: os.Getenv("ALLOWED_CLIENT_IDS")}
	if cfg.Password == "" || cfg.Issuer == "" || cfg.Audience == "" || cfg.JWKSURL == "" || cfg.AllowedClients == "" {
		slog.Error("missing required configuration")
		os.Exit(1)
	}
	u, e := url.Parse(cfg.LLDAPURL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		panic("invalid LLDAP_URL")
	}
	j, e := url.Parse(cfg.JWKSURL)
	if e != nil || j.Scheme != "https" || j.Host == "" || j.User != nil {
		panic("OIDC_JWKS_URL must be HTTPS")
	}
	a := &App{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /health/ready", a.ready)
	mux.Handle("/api/v1/", a.auth(http.HandlerFunc(a.route)))
	server := &http.Server{Addr: cfg.Listen, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	slog.Info("gateway listening", "addr", cfg.Listen)
	if e := server.ListenAndServe(); e != nil {
		slog.Error("server stopped", "error", e)
		os.Exit(1)
	}
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	jsonOut(w, status, map[string]string{"error": msg})
}
func (a *App) ready(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequestWithContext(r.Context(), "GET", strings.TrimRight(a.cfg.LLDAPURL, "/")+"/", nil)
	resp, e := a.http.Do(req)
	if e != nil {
		fail(w, 503, "lldap unavailable")
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		fail(w, 503, "lldap unavailable")
		return
	}
	jsonOut(w, 200, map[string]string{"status": "ready"})
}
func (a *App) login(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Now().Before(a.tokenUntil) {
		return a.token, nil
	}
	b, _ := json.Marshal(map[string]string{"username": a.cfg.Username, "password": a.cfg.Password})
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(a.cfg.LLDAPURL, "/")+"/auth/simple/login", bytes.NewReader(b))
	if e != nil {
		return "", e
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := a.http.Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("lldap login HTTP %d", resp.StatusCode)
	}
	var result struct {
		Token string `json:"token"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result); e != nil {
		return "", e
	}
	if result.Token == "" {
		return "", errors.New("empty lldap token")
	}
	a.token = result.Token
	a.tokenUntil = time.Now().Add(10 * time.Minute)
	return a.token, nil
}
func (a *App) gql(ctx context.Context, q string, vars any) (json.RawMessage, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, e := a.login(ctx)
		if e != nil {
			return nil, e
		}
		b, _ := json.Marshal(map[string]any{"query": q, "variables": vars})
		req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(a.cfg.LLDAPURL, "/")+"/api/graphql", bytes.NewReader(b))
		if e != nil {
			return nil, e
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, e := a.http.Do(req)
		if e != nil {
			return nil, e
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if e != nil {
			return nil, e
		}
		if resp.StatusCode == 401 && attempt == 0 {
			a.mu.Lock()
			a.token = ""
			a.mu.Unlock()
			continue
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("lldap graphql HTTP %d", resp.StatusCode)
		}
		var result gqlResponse
		if e = json.Unmarshal(raw, &result); e != nil {
			return nil, e
		}
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("lldap rejected operation: %s", result.Errors[0].Message)
		}
		return result.Data, nil
	}
	return nil, errors.New("lldap authentication failed")
}
func readBody(r *http.Request) (map[string]any, error) {
	defer r.Body.Close()
	var v map[string]any
	d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return nil, e
	}
	if v == nil {
		return nil, errors.New("expected object")
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return nil, errors.New("unexpected trailing data")
	}
	return v, nil
}
func extract(data json.RawMessage, key string) (any, error) {
	var v map[string]any
	if e := json.Unmarshal(data, &v); e != nil {
		return nil, e
	}
	return v[key], nil
}
func (a *App) execute(w http.ResponseWriter, r *http.Request, q string, vars any, key string, status int) {
	data, e := a.gql(r.Context(), q, vars)
	if e != nil {
		slog.Warn("upstream request failed", "error", e)
		fail(w, 502, "upstream operation failed")
		return
	}
	v, e := extract(data, key)
	if e != nil {
		fail(w, 502, "invalid upstream response")
		return
	}
	jsonOut(w, status, v)
}

const userFields = `id email displayName firstName lastName creationDate uuid attributes {name value} groups {id displayName}`
const groupFields = `id displayName creationDate uuid attributes {name value}`

func (a *App) route(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		fail(w, 404, "not found")
		return
	}
	method := r.Method
	// Explicit permissions are checked before any upstream access.
	scope := ""
	switch parts[0] {
	case "users":
		if method == "GET" {
			scope = "users:read"
		} else {
			scope = "users:write"
		}
	case "groups":
		if method == "GET" {
			scope = "groups:read"
		} else {
			scope = "groups:write"
		}
	case "schema":
		scope = "schema:read"
	default:
		fail(w, 404, "not found")
		return
	}
	if !hasScope(r.Context(), scope) {
		fail(w, 403, "insufficient scope")
		return
	}
	if parts[0] == "users" {
		switch {
		case len(parts) == 1 && method == "GET":
			a.execute(w, r, `query {users {`+userFields+`}}`, nil, "users", 200)
		case len(parts) == 2 && method == "GET":
			a.execute(w, r, `query($id:String!){user(userId:$id){`+userFields+`}}`, map[string]any{"id": parts[1]}, "user", 200)
		case len(parts) == 1 && method == "POST":
			v, e := readBody(r)
			if e != nil {
				fail(w, 400, "invalid JSON")
				return
			}
			a.execute(w, r, `mutation($input:CreateUserInput!){createUser(user:$input){`+userFields+`}}`, map[string]any{"input": v}, "createUser", 201)
		case len(parts) == 2 && method == "PATCH":
			v, e := readBody(r)
			if e != nil {
				fail(w, 400, "invalid JSON")
				return
			}
			v["id"] = parts[1]
			a.execute(w, r, `mutation($input:UpdateUserInput!){updateUser(user:$input){ok}}`, map[string]any{"input": v}, "updateUser", 200)
		case len(parts) == 2 && method == "DELETE":
			a.execute(w, r, `mutation($id:String!){deleteUser(userId:$id){ok}}`, map[string]any{"id": parts[1]}, "deleteUser", 200)
		default:
			fail(w, 404, "not found")
		}
		return
	}
	if parts[0] == "groups" {
		if len(parts) >= 2 {
			id, e := strconv.Atoi(parts[1])
			if e != nil || id < 1 {
				fail(w, 400, "invalid group id")
				return
			}
			vars := map[string]any{"id": id}
			switch {
			case len(parts) == 2 && method == "GET":
				a.execute(w, r, `query($id:Int!){group(groupId:$id){`+groupFields+` users {id email displayName}}}`, vars, "group", 200)
			case len(parts) == 2 && method == "PATCH":
				v, e := readBody(r)
				if e != nil {
					fail(w, 400, "invalid JSON")
					return
				}
				v["id"] = id
				a.execute(w, r, `mutation($input:UpdateGroupInput!){updateGroup(group:$input){ok}}`, map[string]any{"input": v}, "updateGroup", 200)
			case len(parts) == 2 && method == "DELETE":
				a.execute(w, r, `mutation($id:Int!){deleteGroup(groupId:$id){ok}}`, vars, "deleteGroup", 200)
			case len(parts) == 4 && parts[2] == "members" && (method == "PUT" || method == "DELETE"):
				if !hasScope(r.Context(), "memberships:write") {
					fail(w, 403, "insufficient scope")
					return
				}
				vars["user"] = parts[3]
				op := "addUserToGroup"
				if method == "DELETE" {
					op = "removeUserFromGroup"
				}
				a.execute(w, r, `mutation($user:String!,$id:Int!){`+op+`(userId:$user,groupId:$id){ok}}`, vars, op, 200)
			default:
				fail(w, 404, "not found")
			}
			return
		}
		switch {
		case len(parts) == 1 && method == "GET":
			a.execute(w, r, `query {groups {`+groupFields+`}}`, nil, "groups", 200)
		case len(parts) == 1 && method == "POST":
			v, e := readBody(r)
			if e != nil {
				fail(w, 400, "invalid JSON")
				return
			}
			name, ok := v["displayName"].(string)
			if !ok || name == "" {
				fail(w, 400, "displayName required")
				return
			}
			a.execute(w, r, `mutation($name:String!){createGroup(name:$name){`+groupFields+`}}`, map[string]any{"name": name}, "createGroup", 201)
		default:
			fail(w, 404, "not found")
		}
		return
	}
	if parts[0] == "schema" && len(parts) == 1 && method == "GET" {
		a.execute(w, r, `query {schema {userSchema {attributes {name attributeType isList isVisible isEditable isHardcoded isReadonly} extraLdapObjectClasses} groupSchema {attributes {name attributeType isList isVisible isEditable isHardcoded isReadonly} extraLdapObjectClasses}}}`, nil, "schema", 200)
		return
	}
	fail(w, 404, "not found")
}

type ctxKey struct{}

func hasScope(ctx context.Context, needed string) bool {
	scopes, _ := ctx.Value(ctxKey{}).(map[string]bool)
	return scopes[needed] || scopes["*"]
}
func decodePart(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func (a *App) jwks(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	a.keysMu.Lock()
	defer a.keysMu.Unlock()
	if len(a.keys) > 0 && time.Now().Before(a.keysUntil) {
		return a.keys, nil
	}
	req, e := http.NewRequestWithContext(ctx, "GET", a.cfg.JWKSURL, nil)
	if e != nil {
		return nil, e
	}
	resp, e := a.http.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("jwks fetch failed")
	}
	var raw struct {
		Keys []map[string]string `json:"keys"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); e != nil {
		return nil, e
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range raw.Keys {
		if k["kty"] != "RSA" || k["kid"] == "" || (k["alg"] != "" && k["alg"] != "RS256") || (k["use"] != "" && k["use"] != "sig") {
			continue
		}
		n, e1 := decodePart(k["n"])
		ex, e2 := decodePart(k["e"])
		if e1 != nil || e2 != nil || len(n) < 256 || len(ex) == 0 || len(ex) > 4 {
			continue
		}
		exp := new(big.Int).SetBytes(ex)
		if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<24 {
			continue
		}
		keys[k["kid"]] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}
	}
	if len(keys) == 0 {
		return nil, errors.New("no acceptable signing keys")
	}
	a.keys = keys
	a.keysUntil = time.Now().Add(5 * time.Minute)
	return keys, nil
}
func (a *App) validate(ctx context.Context, tok string) (map[string]bool, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	hb, e := decodePart(parts[0])
	if e != nil {
		return nil, e
	}
	pb, e := decodePart(parts[1])
	if e != nil {
		return nil, e
	}
	sig, e := decodePart(parts[2])
	if e != nil {
		return nil, e
	}
	var h struct{ Alg, Kid, Typ string }
	if e = json.Unmarshal(hb, &h); e != nil || h.Alg != "RS256" || h.Kid == "" {
		return nil, errors.New("unsupported JWT")
	}
	keys, e := a.jwks(ctx)
	if e != nil {
		return nil, e
	}
	key := keys[h.Kid]
	if key == nil {
		return nil, errors.New("unknown signing key")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if e = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig); e != nil {
		return nil, e
	}
	var claims map[string]any
	if e = json.Unmarshal(pb, &claims); e != nil {
		return nil, e
	}
	if claims["iss"] != a.cfg.Issuer {
		return nil, errors.New("issuer mismatch")
	}
	audOK := false
	switch v := claims["aud"].(type) {
	case string:
		audOK = v == a.cfg.Audience
	case []any:
		for _, s := range v {
			if s == a.cfg.Audience {
				audOK = true
			}
		}
	}
	if !audOK {
		return nil, errors.New("audience mismatch")
	}
	now := float64(time.Now().Unix())
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= now {
		return nil, errors.New("expired token")
	}
	if nbf, ok := claims["nbf"].(float64); ok && nbf > now+30 {
		return nil, errors.New("token not yet valid")
	}
	if iat, ok := claims["iat"].(float64); ok && iat > now+30 {
		return nil, errors.New("future issued token")
	}
	client, _ := claims["client_id"].(string)
	if client == "" {
		client, _ = claims["azp"].(string)
	}
	allowed := false
	for _, c := range strings.Split(a.cfg.AllowedClients, ",") {
		if strings.TrimSpace(c) == client && client != "" {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("client not allowed")
	}
	scopes := map[string]bool{}
	if s, ok := claims["scope"].(string); ok {
		for _, x := range strings.Fields(s) {
			scopes[x] = true
		}
	}
	if s, ok := claims["scp"].([]any); ok {
		for _, x := range s {
			if v, ok := x.(string); ok {
				scopes[v] = true
			}
		}
	}
	return scopes, nil
}
func (a *App) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			fail(w, 401, "bearer token required")
			return
		}
		scopes, e := a.validate(r.Context(), strings.TrimPrefix(header, "Bearer "))
		if e != nil {
			slog.Warn("access denied", "reason", e.Error())
			fail(w, 401, "invalid token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, scopes)))
	})
}
