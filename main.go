package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct{ LLDAPURL, Username, Password, Listen string }
type App struct {
	cfg        Config
	http       *http.Client
	mu         sync.Mutex
	token      string
	tokenUntil time.Time
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
	cfg := Config{LLDAPURL: env("LLDAP_URL", "http://lldap:17170"), Username: env("LLDAP_USERNAME", "admin"), Password: secret("LLDAP_PASSWORD"), Listen: env("LISTEN_ADDR", ":8080")}
	if cfg.Password == "" {
		slog.Error("missing required configuration")
		os.Exit(1)
	}
	u, e := url.Parse(cfg.LLDAPURL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		panic("invalid LLDAP_URL")
	}
rpm, e := strconv.Atoi(env("RATE_LIMIT_PER_MINUTE","60"))
 if e != nil {slog.Error("invalid RATE_LIMIT_PER_MINUTE");os.Exit(1)}
 authenticator, e := loadAuthenticator(os.Getenv("CLIENTS_FILE"),rpm)
 if e != nil {slog.Error("invalid client configuration","error",e);os.Exit(1)}
	a := &App{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /health/ready", a.ready)
	mux.Handle("/api/v1/", authenticator.middleware(http.HandlerFunc(a.route)))
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
	d := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return nil, e
	}
	if v == nil {
		return nil, errors.New("expected object")
	}
	if r.ContentLength > 1<<20 {return nil, errors.New("request body too large")}
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
			scope = map[string]string{"POST":"users:create","PATCH":"users:update","DELETE":"users:delete"}[method]
		}
	case "groups":
		if method == "GET" {
			scope = "groups:read"
		} else {
			scope = map[string]string{"POST":"groups:create","PATCH":"groups:update","DELETE":"groups:delete"}[method]
		}
	case "schema":
		scope = "schema:read"
	default:
		fail(w, 404, "not found")
		return
	}
	if scope == "" {fail(w,405,"method not allowed");return}
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
