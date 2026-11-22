package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJWTAndScopes(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "test", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer server.Close()
	a := &App{cfg: Config{Issuer: "issuer", Audience: "api", JWKSURL: server.URL, AllowedClients: "app"}, http: server.Client()}
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	header := enc(map[string]any{"alg": "RS256", "kid": "test"})
	payload := enc(map[string]any{"iss": "issuer", "aud": "api", "client_id": "app", "exp": time.Now().Add(time.Hour).Unix(), "scope": "users:read groups:read"})
	signed := header + "." + payload
	h := sha256.Sum256([]byte(signed))
	sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if e != nil {
		t.Fatal(e)
	}
	scopes, e := a.validate(context.Background(), signed+"."+base64.RawURLEncoding.EncodeToString(sig))
	if e != nil {
		t.Fatal(e)
	}
	if !scopes["users:read"] || scopes["users:write"] {
		t.Fatal("unexpected scopes")
	}
	if _, e = a.validate(context.Background(), signed+".bad"); e == nil {
		t.Fatal("accepted bad signature")
	}
}
