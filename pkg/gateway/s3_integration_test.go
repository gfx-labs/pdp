package gateway

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/pkg/credential"
)

// This test requires an authenticated disposable S3 server, not an HTTP mock.
// Set PDP_TEST_S3_ENDPOINT, PDP_TEST_S3_ACCESS_KEY and PDP_TEST_S3_SECRET_KEY.
func TestS3SigningIntegration(t *testing.T) {
	endpoint := os.Getenv("PDP_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("PDP_TEST_S3_ENDPOINT is not set")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		t.Fatal("expected a disposable plain HTTP S3 endpoint")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, value := range map[string]string{"access": os.Getenv("PDP_TEST_S3_ACCESS_KEY"), "secret": os.Getenv("PDP_TEST_S3_SECRET_KEY")} {
		if value == "" {
			t.Fatalf("missing S3 %s", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	manager := func() *credential.Manager {
		m, err := credential.New(credential.Config{
			Providers: map[string]credential.ProviderConfig{"s3": {Script: "def acquire(request):\n    return aws_sigv4(secret(\"access\"), secret(\"secret\"), region=\"us-east-1\")\n"}},
			Bindings:  map[string]credential.BindingConfig{"snapshots": {Provider: "s3", Secrets: map[string]credential.SecretSource{"access": {File: filepath.Join(dir, "access")}, "secret": {File: filepath.Join(dir, "secret")}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	h := newHarness(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected test upstream") }, true, Options{})
	bucket := fmt.Sprintf("pdp-sigv4-%d", time.Now().UnixNano())
	prefix := "/" + bucket + "/sessions/one/"
	engine := engineFor(t, "s3", fmt.Sprintf(`package pdp.authz
import rego.v1
default allow := false
allow if {
  %s
  input.destination.scheme == "http"
  input.destination.host == %q
  input.destination.port == %d
  input.binding == "snapshots"
  permitted_path
  valid_source
}
permitted_path if startswith(input.http.path, %q)
permitted_path if { input.http.path == %q; input.http.method in {"GET", "PUT", "DELETE"} }
valid_source if not input.http.headers["x-amz-copy-source"]
valid_source if {
  values := input.http.headers["x-amz-copy-source"]
  count(values) == 1
  startswith(values[0], %q)
}
`, callerRule(true), u.Hostname(), port, prefix, "/"+bucket, prefix), nil)
	up := Upstream{Host: u.Hostname(), Port: port, Bindings: []string{"snapshots"}, PolicyHeaders: []string{"x-amz-copy-source"}}
	h.install(t, "s3-http-default", engine, manager(), up)
	client := h.proxyClient(t, nil)
	request := func(method, path string, body io.Reader, headers http.Header, want int) ([]byte, http.Header) {
		t.Helper()
		req, err := http.NewRequest(method, endpoint+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if headers != nil {
			req.Header = headers
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s: HTTP %d, want %d: %s", method, path, response.StatusCode, want, data)
		}
		return data, response.Header
	}
	request("PUT", "/"+bucket, nil, nil, 400)
	up.AllowHTTP = true
	h.install(t, "s3-http-explicit", engine, manager(), up)
	request("PUT", "/"+bucket, nil, nil, 200)
	t.Cleanup(func() { request("DELETE", "/"+bucket, nil, nil, 204) })
	lifecycle := `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>incomplete-snapshots</ID><Status>Enabled</Status><Filter><Prefix>sessions/</Prefix></Filter><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>`
	request("PUT", "/"+bucket+"?lifecycle", strings.NewReader(lifecycle), http.Header{"Content-Type": {"application/xml"}}, 200)
	configuration, _ := request("GET", "/"+bucket+"?lifecycle", nil, nil, 200)
	if !bytes.Contains(configuration, []byte("<DaysAfterInitiation>1</DaysAfterInitiation>")) {
		t.Fatalf("real S3 did not retain incomplete multipart expiration: %s", configuration)
	}
	key := prefix + "workspace space+$%25.tar.zst"
	payload := []byte("snapshot through PDP, with an unsigned streamed body")
	// io.NopCloser deliberately has no GetBody, like a multipart upload stream.
	request("PUT", key, io.NopCloser(bytes.NewReader(payload)), http.Header{"X-Amz-Content-Sha256": {"caller-placeholder-hash"}, "Authorization": {"caller-placeholder"}}, 200)
	got, _ := request("GET", key, nil, nil, 200)
	if !bytes.Equal(got, payload) {
		t.Fatal("streamed PUT/GET changed the body")
	}
	request("HEAD", key, nil, nil, 200)
	request("GET", "/"+bucket+"/sessions/two/workspace.tar.zst", nil, nil, 403)
	request("PUT", prefix+"copy", nil, http.Header{"X-Amz-Copy-Source": {"/" + bucket + "/sessions/two/workspace.tar.zst"}}, 403)
	request("PUT", prefix+"copy", nil, http.Header{"X-Amz-Copy-Source": {key}}, 200)
	request("DELETE", prefix+"copy", nil, nil, 204)
	request("DELETE", key, nil, nil, 204)

	// Exercise the S3 multipart protocol used by minio-go's unknown-size PUT.
	key = prefix + "multipart"
	data, _ := request("POST", key+"?uploads", nil, nil, 200)
	var upload struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(data, &upload); err != nil || upload.UploadID == "" {
		t.Fatalf("missing upload ID: %s", data)
	}
	query := "?partNumber=1&uploadId=" + url.QueryEscape(upload.UploadID)
	_, headers := request("PUT", key+query, io.NopCloser(bytes.NewReader(payload)), nil, 200)
	complete := "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" + headers.Get("ETag") + "</ETag></Part></CompleteMultipartUpload>"
	request("POST", key+"?uploadId="+url.QueryEscape(upload.UploadID), strings.NewReader(complete), nil, 200)
	got, _ = request("GET", key, nil, nil, 200)
	if !bytes.Equal(got, payload) {
		t.Fatal("multipart upload changed the body")
	}
	request("DELETE", key, nil, nil, 204)
	data, _ = request("POST", key+"?uploads", nil, nil, 200)
	if err := xml.Unmarshal(data, &upload); err != nil {
		t.Fatal(err)
	}
	request("DELETE", key+"?uploadId="+url.QueryEscape(upload.UploadID), nil, nil, 204)

	// Prove the real service enforces authentication, rather than accepting all.
	direct := &http.Client{Timeout: 10 * time.Second}
	m := manager()
	defer m.Close()
	lease, err := m.Get(context.Background(), credential.Request{Provider: "s3", Binding: "snapshots"})
	if err != nil {
		t.Fatal(err)
	}
	for _, signed := range []bool{false, true} {
		req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint+prefix+"not-there", nil)
		if err != nil {
			t.Fatal(err)
		}
		if signed {
			if err := lease.ApplyRequest(req); err != nil {
				t.Fatal(err)
			}
			authorization := req.Header.Get("Authorization")
			req.Header.Set("Authorization", authorization[:strings.LastIndex(authorization, "Signature=")]+"Signature="+strings.Repeat("0", 64))
		}
		response, err := direct.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatalf("real S3 accepted invalid credentials: HTTP %d", response.StatusCode)
		}
	}
}
