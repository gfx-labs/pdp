package credential

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.starlark.net/starlark"
)

// ApplyRequest applies a credential after authorization to the final request.
// Streams without GetBody are not consumed or buffered to sign them.
func (r Result) ApplyRequest(req *http.Request) error {
	if req == nil || req.URL == nil || req.Header == nil {
		return failure(CodeInvalid)
	}
	if r.Kind != AWSSigV4 {
		return r.Apply(req.Header)
	}
	if r.token == "" || r.accessKey == "" || !time.Now().Before(r.ExpiresAt) {
		return failure(CodeUnavailable)
	}
	return r.signV4(req, time.Now().UTC())
}

func (e *execution) awsSigV4(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var access, secret starlark.Value
	var region string
	service := "s3"
	ttl := 300
	if err := starlark.UnpackArgs(b.Name(), args, kw, "access_key", &access, "secret_key", &secret, "region", &region, "service?", &service, "ttl_seconds?", &ttl); err != nil {
		return nil, err
	}
	accessHandle, accessOK := access.(*secretHandle)
	secretHandle, secretOK := secret.(*secretHandle)
	if !accessOK || !secretOK || !validScope(region) || !validScope(service) || ttl <= 0 || ttl > 86400 {
		return nil, failure(CodeInvalid)
	}
	accessBytes, err := e.material(accessHandle)
	if err != nil {
		return nil, err
	}
	secretBytes, err := e.material(secretHandle)
	if err != nil {
		return nil, err
	}
	if !validValue(string(accessBytes), 1024) || strings.ContainsAny(string(accessBytes), "/, ") || !validValue(string(secretBytes), 4096) {
		return nil, failure(CodeInvalid)
	}
	r := Result{Kind: AWSSigV4, accessKey: string(accessBytes), token: string(secretBytes), region: region, service: service, ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second)}
	return &resultValue{result: r, owner: e}, nil
}

func validScope(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// awsEncode uses RFC 3986 bytes, not form encoding's plus for a space.
func awsEncode(value string, path bool) string {
	const digits = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~", rune(c)) || path && c == '/' {
			out.WriteByte(c)
		} else {
			out.WriteByte('%')
			out.WriteByte(digits[c>>4])
			out.WriteByte(digits[c&15])
		}
	}
	return out.String()
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func hmacSHA256(key []byte, value string) []byte {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(value))
	return hash.Sum(nil)
}

func (r Result) signV4(req *http.Request, now time.Time) error {
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return failure(CodeInvalid)
	}
	var pairs []string
	for key, values := range query {
		// Never combine caller presigning with the proxy's credential.
		if strings.HasPrefix(strings.ToLower(key), "x-amz-") || strings.EqualFold(key, "AWSAccessKeyId") || strings.EqualFold(key, "Signature") {
			return failure(CodeInvalid)
		}
		for _, value := range values {
			pairs = append(pairs, awsEncode(key, false)+"="+awsEncode(value, false))
		}
	}
	sort.Strings(pairs)
	// Signed chunks contain the caller's signature and cannot be re-signed.
	if req.Header.Get("X-Amz-Decoded-Content-Length") != "" || strings.Contains(strings.ToLower(req.Header.Get("Content-Encoding")), "aws-chunked") {
		return failure(CodeInvalid)
	}
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Security-Token")
	payload := "UNSIGNED-PAYLOAD"
	if req.Body == nil || req.Body == http.NoBody {
		payload = sha256Hex(nil)
	} else if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return failure(CodeUnavailable)
		}
		hash := sha256.New()
		_, readErr := io.Copy(hash, body)
		closeErr := body.Close()
		if readErr != nil || closeErr != nil {
			return failure(CodeUnavailable)
		}
		payload = hex.EncodeToString(hash.Sum(nil))
	}
	req.Header.Set("X-Amz-Content-Sha256", payload)
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	headers := map[string]string{"host": req.URL.Host}
	if req.Host != "" {
		headers["host"] = req.Host
	}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") || lower == "content-type" || lower == "content-md5" || lower == "range" || lower == "date" {
			normalized := make([]string, len(values))
			for i, value := range values {
				normalized[i] = strings.Join(strings.Fields(value), " ")
			}
			headers[lower] = strings.Join(normalized, ",")
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + headers[name] + "\n")
	}
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	// S3 keys must retain repeated slashes, without path cleaning.
	signedHeaders := strings.Join(names, ";")
	canonical := strings.Join([]string{req.Method, awsEncode(path, true), strings.Join(pairs, "&"), canonicalHeaders.String(), signedHeaders, payload}, "\n")
	date := now.Format("20060102")
	scope := date + "/" + r.region + "/" + r.service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + now.Format("20060102T150405Z") + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	key := hmacSHA256([]byte("AWS4"+r.token), date)
	key = hmacSHA256(key, r.region)
	key = hmacSHA256(key, r.service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+r.accessKey+"/"+scope+",SignedHeaders="+signedHeaders+",Signature="+signature)
	return nil
}
