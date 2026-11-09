package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const help = `pdp is an identity-aware provider credential gateway.

Commands:
  serve       Serve a validated configuration, SIGHUP reloads it atomically
  validate    Validate configuration, schemas, policy and credential adapters offline
  explain     Evaluate a trusted policy input offline, without upstream requests
  catalog     Print a schema operation catalog as JSON
  schema diff Compare two schema operation catalogs
  request     Send an HTTP request over the local Unix gateway socket

Run pdp COMMAND --help for options.
`

func run(args []string, out, errout io.Writer) error {
	if len(args) == 0 {
		_, err := io.WriteString(out, help)
		return err
	}
	switch args[0] {
	case "help", "--help", "-h":
		_, err := io.WriteString(out, help)
		return err
	case "serve":
		return serveCommand(args[1:], out, errout)
	case "validate":
		return validateCommand(args[1:], out, errout)
	case "explain":
		return explainCommand(args[1:], out, errout)
	case "catalog":
		return catalogCommand(args[1:], out, errout)
	case "schema":
		return schemaCommand(args[1:], out, errout)
	case "request":
		return requestCommand(args[1:], out, errout)
	default:
		return errors.New("unknown command, run pdp --help")
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "pdp:", err)
		os.Exit(1)
	}
}

func requestCommand(args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	fs.SetOutput(errout)
	socket := fs.String("socket", "/run/pdp/pdp.sock", "Unix gateway socket")
	method := fs.String("method", "GET", "HTTP method")
	path := fs.String("path", "", "gateway path, for example /upstreams/github/repos/owner/repo")
	bodyFile := fs.String("body", "", "request body file, or - for stdin")
	contentType := fs.String("content-type", "application/json", "request content type")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *path == "" || *timeout <= 0 {
		return errors.New("usage: pdp request --socket PATH --path /upstreams/PROVIDER/PATH [--method GET] [--body FILE]")
	}
	u, err := url.ParseRequestURI(*path)
	if err != nil || !strings.HasPrefix(*path, "/") || strings.HasPrefix(*path, "//") || u.Host != "" || u.Scheme != "" {
		return errors.New("request path must be a relative gateway path beginning with /")
	}
	var body io.Reader
	if *bodyFile == "-" {
		body = io.LimitReader(os.Stdin, (1<<20)+1)
	} else if *bodyFile != "" {
		b, err := readLimited(*bodyFile, 1<<20)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(b))
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, *method, "http://pdp"+*path, body)
	if err != nil {
		return errors.New("invalid HTTP request")
	}
	if body != nil {
		req.Header.Set("Content-Type", *contentType)
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("gateway request failed")
	}
	defer resp.Body.Close()
	n, err := io.Copy(out, io.LimitReader(resp.Body, (32<<20)+1))
	if err != nil || n > 32<<20 {
		return errors.New("gateway response is unreadable or exceeds 32 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gateway returned HTTP %d", resp.StatusCode)
	}
	return nil
}
