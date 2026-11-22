package main

import (
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "log/slog"
 "net/http"
 "os"
 "strings"
 "sync"
 "time"
)

type clientConfig struct {
 Name string `json:"name"`
 KeySHA256 string `json:"key_sha256"`
 Permissions []string `json:"permissions"`
}
type client struct {
 name string
 hash [32]byte
 permissions map[string]bool
}
type clientContextKey struct{}
type limiterEntry struct { count int; reset time.Time }
type authenticator struct {
 clients []client
 mu sync.Mutex
 limits map[string]limiterEntry
 requestsPerMinute int
}
var validPermissions = map[string]bool{
 "users:read":true, "users:create":true, "users:update":true, "users:delete":true,
 "groups:read":true, "groups:create":true, "groups:update":true, "groups:delete":true,
 "memberships:write":true, "schema:read":true,
}
func loadAuthenticator(path string, rpm int) (*authenticator,error) {
 if path=="" {return nil,errors.New("CLIENTS_FILE is required")}
 if rpm<1 || rpm>100000 {return nil,errors.New("RATE_LIMIT_PER_MINUTE must be between 1 and 100000")}
 raw,err:=os.ReadFile(path); if err!=nil{return nil,err}
 var configs []clientConfig
 decoder:=json.NewDecoder(strings.NewReader(string(raw)))
 decoder.DisallowUnknownFields()
 if err=decoder.Decode(&configs);err!=nil{return nil,fmt.Errorf("invalid clients JSON: %w",err)}
 if len(configs)==0 || len(configs)>100 {return nil,errors.New("clients count must be 1..100")}
 a:=&authenticator{limits:map[string]limiterEntry{},requestsPerMinute:rpm}
 seenNames:=map[string]bool{}; seenHashes:=map[[32]byte]bool{}
 for _,c:=range configs {
  if len(c.Name)<1 || len(c.Name)>64 || seenNames[c.Name] {return nil,errors.New("invalid or duplicate client name")}
  seenNames[c.Name]=true
  b,e:=hex.DecodeString(c.KeySHA256)
  if e!=nil || len(b)!=32 {return nil,fmt.Errorf("client %q requires 64-character SHA-256 hex digest",c.Name)}
  var h [32]byte;copy(h[:],b)
  if seenHashes[h] {return nil,errors.New("duplicate key digest")}
  seenHashes[h]=true
  if len(c.Permissions)==0 {return nil,fmt.Errorf("client %q has no permissions",c.Name)}
  perms:=map[string]bool{}
  for _,p:=range c.Permissions {
   if !validPermissions[p] {return nil,fmt.Errorf("invalid permission %q",p)}
   perms[p]=true
  }
  a.clients=append(a.clients,client{name:c.Name,hash:h,permissions:perms})
 }
 return a,nil
}
func (a *authenticator) middleware(next http.Handler) http.Handler {
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  keys,ok:=r.Header["X-Api-Key"]
  if !ok || len(keys)!=1 || len(keys[0])<32 || len(keys[0])>4096 {
   fail(w,401,"invalid API key");return
  }
  hash:=sha256.Sum256([]byte(keys[0]))
  matched:=-1
  for i,c:=range a.clients {
   if subtle.ConstantTimeCompare(hash[:],c.hash[:])==1 {matched=i}
  }
  if matched<0 {fail(w,401,"invalid API key");return}
  c:=a.clients[matched]
  now:=time.Now()
  a.mu.Lock()
  entry:=a.limits[c.name]
  if now.After(entry.reset) {entry=limiterEntry{reset:now.Add(time.Minute)}}
  entry.count++
  a.limits[c.name]=entry
  exceeded:=entry.count>a.requestsPerMinute
  a.mu.Unlock()
  if exceeded {
   w.Header().Set("Retry-After","60")
   fail(w,429,"rate limit exceeded");return
  }
  start:=time.Now()
  rec:=&statusRecorder{ResponseWriter:w,status:200}
  ctx:=context.WithValue(r.Context(),ctxKey{},c.permissions)
  ctx=context.WithValue(ctx,clientContextKey{},c.name)
  next.ServeHTTP(rec,r.WithContext(ctx))
  auditRequest(c.name,r.Method,r.URL.Path,rec.status,time.Since(start))
 })
}
type statusRecorder struct{http.ResponseWriter;status int}
func (w *statusRecorder) WriteHeader(status int){w.status=status;w.ResponseWriter.WriteHeader(status)}
func auditRequest(clientName,method,path string,status int,duration time.Duration){
 // Do not log query strings, request bodies, credentials, or user identifiers in path.
 route:="/api/v1/other"
 if strings.HasPrefix(path,"/api/v1/users"){route="/api/v1/users"}
 if strings.HasPrefix(path,"/api/v1/groups"){route="/api/v1/groups"}
 if strings.HasPrefix(path,"/api/v1/schema"){route="/api/v1/schema"}
 slog.Info("api request", "client",clientName,"method",method,"route",route,"status",status,"duration_ms",duration.Milliseconds())
}
