package main

import (
 "context"
 "crypto/sha256"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestAPIKeyAuthentication(t *testing.T) {
 key := strings.Repeat("a", 48)
 app := &App{cfg: Config{APIKeyHash: sha256.Sum256([]byte(key))}}
 handler := app.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if !hasScope(r.Context(), "users:write") { t.Error("authenticated request lacks permission") }
  w.WriteHeader(http.StatusNoContent)
 }))
 for _, tc := range []struct{name, key string; status int}{
  {"valid", key, http.StatusNoContent},
  {"missing", "", http.StatusUnauthorized},
  {"wrong", strings.Repeat("b", 48), http.StatusUnauthorized},
  {"short", "abc", http.StatusUnauthorized},
 } {
  t.Run(tc.name, func(t *testing.T) {
   req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
   if tc.key != "" { req.Header.Set("X-API-Key", tc.key) }
   rec := httptest.NewRecorder()
   handler.ServeHTTP(rec, req)
   if rec.Code != tc.status { t.Fatalf("status %d, want %d", rec.Code, tc.status) }
  })
 }
}

func TestMissingScope(t *testing.T) {
 if hasScope(context.Background(), "users:read") { t.Fatal("unauthenticated scope accepted") }
}
