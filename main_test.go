package main

import (
 "crypto/sha256"
 "encoding/hex"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func testAuthenticator(t *testing.T, rpm int) (*authenticator,string) {
 t.Helper()
 key:=strings.Repeat("a",64)
 h:=sha256.Sum256([]byte(key))
 path:=filepath.Join(t.TempDir(),"clients.json")
 data:=fmt.Sprintf(`[{"name":"reader","key_sha256":"%s","permissions":["users:read"]}]`,hex.EncodeToString(h[:]))
 if err:=os.WriteFile(path,[]byte(data),0600);err!=nil{t.Fatal(err)}
 a,err:=loadAuthenticator(path,rpm);if err!=nil{t.Fatal(err)}
 return a,key
}
func TestAuthenticationAndPermissions(t *testing.T){
 a,key:=testAuthenticator(t,60)
 h:=a.middleware(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if !hasScope(r.Context(),"users:read") || hasScope(r.Context(),"users:delete"){t.Error("incorrect scopes")}
  w.WriteHeader(204)
 }))
 for _,tc:=range []struct{name,key string;want int}{
  {"valid",key,204},{"missing","",401},{"wrong",strings.Repeat("b",64),401},{"short","abc",401},
 }{
  t.Run(tc.name,func(t *testing.T){
   req:=httptest.NewRequest("GET","/api/v1/users",nil)
   if tc.key!=""{req.Header.Set("X-API-Key",tc.key)}
   rec:=httptest.NewRecorder();h.ServeHTTP(rec,req)
   if rec.Code!=tc.want{t.Fatalf("got %d want %d",rec.Code,tc.want)}
  })
 }
}
func TestRateLimit(t *testing.T){
 a,key:=testAuthenticator(t,1)
 h:=a.middleware(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(204)}))
 for i,want:=range []int{204,429}{
  req:=httptest.NewRequest("GET","/api/v1/users",nil);req.Header.Set("X-API-Key",key)
  rec:=httptest.NewRecorder();h.ServeHTTP(rec,req)
  if rec.Code!=want{t.Fatalf("request %d: got %d want %d",i,rec.Code,want)}
 }
}
func TestInvalidClientConfig(t *testing.T){
 p:=filepath.Join(t.TempDir(),"clients.json")
 for _,body:=range []string{`[]`,`[{"name":"x","key_sha256":"bad","permissions":["users:read"]}]`,`[{"name":"x","key_sha256":"`+strings.Repeat("a",64)+`","permissions":["*"]}]`}{
  if err:=os.WriteFile(p,[]byte(body),0600);err!=nil{t.Fatal(err)}
  if _,err:=loadAuthenticator(p,60);err==nil{t.Fatalf("accepted invalid configuration: %s",body)}
 }
}
func TestReadOnlyClientCannotDelete(t *testing.T){
 a,key:=testAuthenticator(t,60)
 app:=&App{}
 h:=a.middleware(http.HandlerFunc(app.route))
 req:=httptest.NewRequest("DELETE","/api/v1/users/test",nil);req.Header.Set("X-API-Key",key)
 rec:=httptest.NewRecorder();h.ServeHTTP(rec,req)
 if rec.Code!=403{t.Fatalf("got %d, want 403",rec.Code)}
}
