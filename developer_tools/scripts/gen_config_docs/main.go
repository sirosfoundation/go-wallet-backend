// Package main generates docs/CONFIGURATION.md from Go struct definitions.
//
// It parses config struct files using go/ast and extracts YAML keys, envconfig
// tags, types, and comments (both doc comments and inline comments) to produce
// a comprehensive Markdown configuration reference.
//
// Usage:
//
//	go run developer_tools/scripts/gen_config_docs/main.go [-root /path/to/project] [-out docs/CONFIGURATION.md]
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FieldDoc represents a documented config field.
type FieldDoc struct {
	YAMLPath    string
	EnvVar      string
	GoType      string
	Description string
	Default     string
}

// SectionDoc represents a top-level config section.
type SectionDoc struct {
	Title       string
	Description string
	Prefix      string // YAML path prefix
	EnvPrefix   string // env prefix (e.g. WALLET_SERVER)
	Fields      []FieldDoc
}

// StructInfo holds parsed struct metadata.
type StructInfo struct {
	Name   string
	Doc    string
	Fields []FieldInfo
}

// FieldInfo holds parsed field metadata.
type FieldInfo struct {
	GoName    string
	GoType    string
	YAMLTag   string
	EnvTag    string
	Doc       string
	InlineDoc string // trailing comment (e.g., `// Admin API bind address`)
	TypeName  string // resolved struct type name, if embedded struct
	Omitempty bool
}

// Registry of all parsed struct types, keyed by pkg.TypeName.
type Registry struct {
	types map[string]*StructInfo
	fset  *token.FileSet
}

func NewRegistry() *Registry {
	return &Registry{
		types: make(map[string]*StructInfo),
		fset:  token.NewFileSet(),
	}
}

func (r *Registry) ParseDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := parser.ParseFile(r.fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		pkgName := file.Name.Name
		r.extractStructs(file, pkgName)
	}
	return nil
}

func (r *Registry) extractStructs(file *ast.File, pkgName string) {
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			info := &StructInfo{
				Name: ts.Name.Name,
				Doc:  cleanDoc(gd.Doc),
			}
			for _, field := range st.Fields.List {
				if len(field.Names) == 0 {
					continue // skip embedded
				}
				fi := FieldInfo{
					GoName:    field.Names[0].Name,
					GoType:    typeString(field.Type),
					Doc:       cleanDoc(field.Doc),
					InlineDoc: cleanInlineComment(field.Comment),
				}
				// Check if the type references another struct (qualify with package)
				fi.TypeName = resolveTypeName(field.Type, pkgName)

				if field.Tag != nil {
					tag := strings.Trim(field.Tag.Value, "`")
					fi.YAMLTag = extractTag(tag, "yaml")
					fi.EnvTag = extractTag(tag, "envconfig")
					fi.Omitempty = strings.Contains(fi.YAMLTag, ",omitempty")
					fi.YAMLTag = strings.Split(fi.YAMLTag, ",")[0]
				}
				// Skip unexported or fields with yaml:"-"
				if fi.YAMLTag == "-" || !ast.IsExported(fi.GoName) {
					continue
				}
				info.Fields = append(info.Fields, fi)
			}
			// Store with qualified key (pkg.Name) and simple key (Name)
			r.types[pkgName+"."+info.Name] = info
			// Only store unqualified if not already present (first-parsed wins)
			if _, exists := r.types[info.Name]; !exists {
				r.types[info.Name] = info
			}
		}
	}
}

func resolveTypeName(expr ast.Expr, currentPkg string) string {
	switch t := expr.(type) {
	case *ast.Ident:
		if ast.IsExported(t.Name) {
			// Qualify local type references with the current package
			return currentPkg + "." + t.Name
		}
	case *ast.SelectorExpr:
		// Return "pkg.Type" for qualified references like embed.Config
		if x, ok := t.X.(*ast.Ident); ok {
			return x.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.StarExpr:
		return resolveTypeName(t.X, currentPkg)
	}
	return ""
}

func typeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok {
			return x.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	case *ast.ArrayType:
		return "[]" + typeString(t.Elt)
	case *ast.MapType:
		return "map[" + typeString(t.Key) + "]" + typeString(t.Value)
	case *ast.InterfaceType:
		return "interface{}"
	default:
		return "unknown"
	}
}

func extractTag(tag, key string) string {
	// Find key:"value" in struct tag string
	search := key + `:"`
	idx := strings.Index(tag, search)
	if idx < 0 {
		return ""
	}
	rest := tag[idx+len(search):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func cleanDoc(cg *ast.CommentGroup) string {
	if cg == nil {
		return ""
	}
	var lines []string
	for _, c := range cg.List {
		text := c.Text
		text = strings.TrimPrefix(text, "//")
		text = strings.TrimPrefix(text, " ")
		lines = append(lines, text)
	}
	return strings.TrimSpace(strings.Join(lines, " "))
}

func cleanInlineComment(cg *ast.CommentGroup) string {
	if cg == nil {
		return ""
	}
	var parts []string
	for _, c := range cg.List {
		text := strings.TrimPrefix(c.Text, "//")
		text = strings.TrimSpace(text)
		if text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, " ")
}

// LookupFrom finds a struct by name, preferring types from preferPkg.
// This prevents cross-package collisions (e.g., registry.ServerConfig vs config.ServerConfig).
func (r *Registry) LookupFrom(name, preferPkg string) *StructInfo {
	// Direct qualified match
	if s, ok := r.types[name]; ok {
		return s
	}
	// For qualified names like "pkgconfig.HTTPClientConfig" or "embed.Config"
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		pkgAlias := name[:idx]
		simple := name[idx+1:]
		// Try exact package match first
		for key, s := range r.types {
			if strings.HasSuffix(key, "."+simple) {
				keyPkg := key[:strings.LastIndex(key, ".")]
				if keyPkg == pkgAlias || strings.HasSuffix(keyPkg, pkgAlias) {
					return s
				}
			}
		}
		// Fallback: try simple name but prefer preferPkg
		if preferPkg != "" {
			if s, ok := r.types[preferPkg+"."+simple]; ok {
				return s
			}
		}
		if s, ok := r.types[simple]; ok {
			return s
		}
		return nil
	}
	// Unqualified name — prefer the type from preferPkg
	if preferPkg != "" {
		if s, ok := r.types[preferPkg+"."+name]; ok {
			return s
		}
	}
	if s, ok := r.types[name]; ok {
		return s
	}
	return nil
}

// buildSections produces documentation sections from the root config struct.
// preferPkg is the package name whose types should be preferred for ambiguous lookups.
func buildSections(reg *Registry, rootName, envPrefix, preferPkg string) []SectionDoc {
	root := reg.LookupFrom(rootName, preferPkg)
	if root == nil {
		log.Fatalf("root struct %q not found in parsed types", rootName)
	}

	var sections []SectionDoc
	var rootFields []FieldDoc // collect scalar/unresolvable root fields

	for _, field := range root.Fields {
		yamlKey := field.YAMLTag
		if yamlKey == "" {
			yamlKey = strings.ToLower(field.GoName)
		}
		envKey := field.EnvTag
		if envKey == "" {
			envKey = strings.ToUpper(field.GoName)
		}
		sectionEnv := envPrefix + "_" + envKey

		// If the field references a struct, expand it as a section
		sub := reg.LookupFrom(field.TypeName, preferPkg)
		if sub != nil {
			sec := SectionDoc{
				Title:       yamlKey,
				Description: fieldDescription(field),
				Prefix:      yamlKey,
				EnvPrefix:   sectionEnv,
			}
			sec.Fields = flattenStruct(reg, sub, yamlKey, sectionEnv, 0, preferPkg)
			sections = append(sections, sec)
		} else {
			// For slice-of-struct types, try to resolve the element type
			elemType := sliceElementType(field.GoType)
			elemSub := reg.LookupFrom(elemType, preferPkg)
			if elemSub != nil {
				// Create a section showing the struct fields within the slice
				sec := SectionDoc{
					Title:       yamlKey,
					Description: fieldDescription(field) + " (list of entries, each with the fields below)",
					Prefix:      yamlKey + "[*]",
					EnvPrefix:   sectionEnv,
				}
				sec.Fields = flattenStruct(reg, elemSub, yamlKey+"[*]", sectionEnv, 0, preferPkg)
				sections = append(sections, sec)
			} else {
				// Scalar field at root level
				rootFields = append(rootFields, FieldDoc{
					YAMLPath:    yamlKey,
					EnvVar:      sectionEnv,
					GoType:      friendlyType(field.GoType),
					Description: fieldDescription(field),
				})
			}
		}
	}

	// Prepend root-level fields if any
	if len(rootFields) > 0 {
		sections = append([]SectionDoc{{
			Title:     "general",
			EnvPrefix: envPrefix,
			Fields:    rootFields,
		}}, sections...)
	}

	return sections
}

func flattenStruct(reg *Registry, info *StructInfo, pathPrefix, envPrefix string, depth int, preferPkg string) []FieldDoc {
	if depth > 5 {
		return nil // guard against cycles
	}
	var docs []FieldDoc
	for _, f := range info.Fields {
		yamlKey := f.YAMLTag
		if yamlKey == "" {
			yamlKey = strings.ToLower(f.GoName)
		}
		envKey := f.EnvTag
		if envKey == "" {
			envKey = strings.ToUpper(f.GoName)
		}

		fullPath := pathPrefix + "." + yamlKey
		fullEnv := envPrefix + "_" + envKey

		// If field references another struct, recurse
		sub := reg.LookupFrom(f.TypeName, preferPkg)
		if sub != nil {
			docs = append(docs, flattenStruct(reg, sub, fullPath, fullEnv, depth+1, preferPkg)...)
		} else {
			docs = append(docs, FieldDoc{
				YAMLPath:    fullPath,
				EnvVar:      fullEnv,
				GoType:      friendlyType(f.GoType),
				Description: fieldDescription(f),
			})
		}
	}
	return docs
}

// fieldDescription returns the best description for a field,
// combining doc comments and inline comments.
func fieldDescription(f FieldInfo) string {
	if f.Doc != "" {
		return f.Doc
	}
	return f.InlineDoc
}

func friendlyType(goType string) string {
	switch goType {
	case "Duration", "time.Duration":
		return "duration"
	case "int", "int64":
		return "integer"
	case "bool":
		return "boolean"
	case "string":
		return "string"
	case "[]string":
		return "string list"
	case "APIMode":
		return "string (`ts11` or `registry`)"
	default:
		if strings.HasPrefix(goType, "[]") {
			return goType[2:] + " list"
		}
		if strings.HasPrefix(goType, "*") {
			return friendlyType(goType[1:])
		}
		return goType
	}
}

// sliceElementType extracts the element type from a "[]TypeName" string.
func sliceElementType(goType string) string {
	if strings.HasPrefix(goType, "[]") {
		return goType[2:]
	}
	return ""
}

// renderMarkdown produces the final Markdown output.
func renderMarkdown(sections []SectionDoc, title string) string {
	var b strings.Builder
	b.WriteString("<!-- Regenerate with: go run developer_tools/scripts/gen_config_docs/main.go -->\n\n")
	b.WriteString("# " + title + "\n\n")
	b.WriteString("This document describes all configuration options for go-wallet-backend.\n")
	b.WriteString("Configuration is loaded from a YAML file and can be overridden by environment variables.\n\n")
	b.WriteString("Environment variables use the prefix `WALLET_` for the main backend and `REGISTRY_` for the registry server.\n\n")
	b.WriteString("## Table of Contents\n\n")

	for _, sec := range sections {
		if sec.Title == "general" {
			continue
		}
		anchor := strings.ToLower(sec.Title)
		anchor = strings.ReplaceAll(anchor, ".", "")
		anchor = strings.ReplaceAll(anchor, " ", "-")
		anchor = strings.ReplaceAll(anchor, "[*]", "")
		fmt.Fprintf(&b, "- [%s](#%s)\n", sec.Title, anchor)
	}
	b.WriteString("\n---\n\n")

	for _, sec := range sections {
		if sec.Title == "general" && sec.EnvPrefix != "" {
			b.WriteString("## General\n\n")
		} else {
			b.WriteString("## " + sec.Title + "\n\n")
		}
		if sec.Description != "" {
			b.WriteString(sec.Description + "\n\n")
		}
		if sec.EnvPrefix != "" {
			fmt.Fprintf(&b, "Environment prefix: `%s`\n\n", sec.EnvPrefix)
		}

		// Write table (skip for marker sections with no fields)
		if len(sec.Fields) > 0 {
			b.WriteString("| YAML Key | Env Variable | Type | Description |\n")
			b.WriteString("|----------|-------------|------|-------------|\n")
			for _, f := range sec.Fields {
				desc := f.Description
				// Escape pipe characters and newlines in description
				desc = strings.ReplaceAll(desc, "|", "\\|")
				desc = strings.ReplaceAll(desc, "\n", " ")
				fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n",
					f.YAMLPath, f.EnvVar, f.GoType, desc)
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

func main() {
	rootFlag := flag.String("root", "", "workspace root (auto-detected from cwd if empty)")
	outFlag := flag.String("out", "docs/CONFIGURATION.md", "output path relative to root")
	flag.Parse()

	root := *rootFlag
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatalf("cannot get working directory: %v", err)
		}
		root = wd
	}

	// Parse main backend config (pkg/config only)
	mainReg := NewRegistry()
	pkgDir := filepath.Join(root, "pkg/config")
	if _, err := os.Stat(pkgDir); err == nil {
		if err := mainReg.ParseDir(pkgDir); err != nil {
			log.Fatalf("error parsing %s: %v", pkgDir, err)
		}
	}
	mainSections := buildSections(mainReg, "config.Config", "WALLET", "config")

	// Parse registry config (internal/registry + internal/embed + pkg/config for cross-refs)
	// Parse pkg/config first so its types are available but internal/registry's Config wins
	regReg := NewRegistry()
	if _, err := os.Stat(pkgDir); err == nil {
		if err := regReg.ParseDir(pkgDir); err != nil {
			log.Fatalf("error parsing %s: %v", pkgDir, err)
		}
	}
	embedDir := filepath.Join(root, "internal/embed")
	if _, err := os.Stat(embedDir); err == nil {
		if err := regReg.ParseDir(embedDir); err != nil {
			log.Fatalf("error parsing %s: %v", embedDir, err)
		}
	}
	regDir := filepath.Join(root, "internal/registry")
	if _, err := os.Stat(regDir); err == nil {
		if err := regReg.ParseDir(regDir); err != nil {
			log.Fatalf("error parsing %s: %v", regDir, err)
		}
	}
	registrySections := buildSections(regReg, "registry.Config", "REGISTRY", "registry")

	// Render combined document
	var allSections []SectionDoc
	allSections = append(allSections, mainSections...)

	// Add registry sections with a heading marker
	registryMarker := SectionDoc{
		Title:       "Registry Server",
		Description: "The registry server (`cmd/registry`) has its own configuration file. It serves VCTM (Verifiable Credential Type Metadata) fetched from upstream registries.",
		EnvPrefix:   "REGISTRY",
	}
	allSections = append(allSections, registryMarker)
	for i := range registrySections {
		registrySections[i].Title = "registry." + registrySections[i].Title
	}
	allSections = append(allSections, registrySections...)

	markdown := renderMarkdown(allSections, "Configuration Reference")

	outPath := filepath.Join(root, *outFlag)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		log.Fatalf("creating output dir: %v", err)
	}
	if err := os.WriteFile(outPath, []byte(markdown), 0o644); err != nil {
		log.Fatalf("writing %s: %v", outPath, err)
	}

	// Print summary
	totalFields := 0
	for _, sec := range allSections {
		totalFields += len(sec.Fields)
	}
	fmt.Printf("Generated %s (%d sections, %d fields)\n", outPath, len(allSections), totalFields)

	// Verify no duplicates in main sections
	seen := make(map[string]bool)
	var dups []string
	for _, sec := range mainSections {
		for _, f := range sec.Fields {
			if seen[f.YAMLPath] {
				dups = append(dups, f.YAMLPath)
			}
			seen[f.YAMLPath] = true
		}
	}
	if len(dups) > 0 {
		sort.Strings(dups)
		fmt.Printf("Warning: duplicate YAML paths: %s\n", strings.Join(dups, ", "))
	}
}
