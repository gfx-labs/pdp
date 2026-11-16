package credential

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// AWS publishes these signatures as an independent implementation test suite:
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
func TestAWSPublishedSigV4Vectors(t *testing.T) {
	r := Result{Kind: AWSSigV4, accessKey: "AKIAIOSFODNN7EXAMPLE", token: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "s3"}
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, method, path, body, signature string
		headers                             http.Header
	}{
		{"get-object", "GET", "/test.txt", "", "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", http.Header{"Range": {"bytes=0-9"}}},
		{"put-object", "PUT", "/test$file.text", "Welcome to Amazon S3.", "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd", http.Header{"Date": {"Fri, 24 May 2013 00:00:00 GMT"}, "X-Amz-Storage-Class": {"REDUCED_REDUNDANCY"}}},
		{"get-lifecycle", "GET", "/?lifecycle", "", "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", http.Header{}},
		{"list-objects", "GET", "/?max-keys=2&prefix=J", "", "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", http.Header{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, "https://examplebucket.s3.amazonaws.com"+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header = tc.headers
			if err := r.signV4(req, now); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(req.Header.Get("Authorization"), "Signature="+tc.signature) {
				t.Fatalf("AWS vector mismatch: %s", req.Header.Get("Authorization"))
			}
		})
	}
}
