package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gfx-labs/pdp/internal/schema"
)

const maxSchemaBytes = 16 << 20

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open input file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("input file is unreadable or exceeds size limit")
	}
	return b, nil
}

func schemaCatalog(protocol, path string) (schema.Catalog, error) {
	b, err := readLimited(path, maxSchemaBytes)
	if err != nil {
		return schema.Catalog{}, err
	}
	switch protocol {
	case "rest", "openapi":
		s, err := schema.CompileREST(b)
		if err != nil {
			return schema.Catalog{}, errors.New("invalid OpenAPI schema")
		}
		return s.Catalog(), nil
	case "graphql":
		s, err := schema.CompileGraphQL(b)
		if err != nil {
			return schema.Catalog{}, errors.New("invalid GraphQL schema")
		}
		return s.Catalog(), nil
	default:
		return schema.Catalog{}, errors.New("protocol must be rest or graphql")
	}
}

func printJSON(w io.Writer, value any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(value)
}

func catalogCommand(args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet("catalog", flag.ContinueOnError)
	fs.SetOutput(errout)
	protocol := fs.String("protocol", "rest", "rest or graphql")
	path := fs.String("schema", "", "schema file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("usage: pdp catalog --protocol rest|graphql --schema FILE")
	}
	catalog, err := schemaCatalog(*protocol, *path)
	if err != nil {
		return err
	}
	return printJSON(out, catalog)
}

func schemaCommand(args []string, out, errout io.Writer) error {
	if len(args) == 0 || args[0] != "diff" {
		return errors.New("usage: pdp schema diff --protocol rest|graphql BEFORE AFTER")
	}
	fs := flag.NewFlagSet("schema diff", flag.ContinueOnError)
	fs.SetOutput(errout)
	protocol := fs.String("protocol", "rest", "rest or graphql")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: pdp schema diff --protocol rest|graphql BEFORE AFTER")
	}
	before, err := schemaCatalog(*protocol, fs.Arg(0))
	if err != nil {
		return fmt.Errorf("before schema: %w", err)
	}
	after, err := schemaCatalog(*protocol, fs.Arg(1))
	if err != nil {
		return fmt.Errorf("after schema: %w", err)
	}
	return printJSON(out, schema.Diff(before, after))
}
