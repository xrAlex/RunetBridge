package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

const (
	defaultRuleGroup  = "common"
	defaultOutputPath = "dist/ru.yaml"
	dnsLookupWorkers  = 24
)

var classicalRuleTypes = map[string]struct{}{
	"DOMAIN":         {},
	"DOMAIN-SUFFIX":  {},
	"DOMAIN-KEYWORD": {},
	"DOMAIN-REGEX":   {},
	"IP-ASN":         {},
	"IP-CIDR":        {},
	"IP-CIDR6":       {},
}

type Options struct {
	ConfigPath   string
	OutputPath   string
	SkipDownload bool
	DeriveCIDR   bool
	Stdout       io.Writer
}

type Config struct {
	Build     BuildConfig      `yaml:"build"`
	Custom    CustomConfig     `yaml:"custom"`
	Providers []ProviderConfig `yaml:"providers"`
}

type BuildConfig struct {
	Output     string `yaml:"output"`
	DeriveCIDR bool   `yaml:"derive_cidr"`
}

type CustomConfig struct {
	TargetDir string              `yaml:"-"`
	Groups    map[string][]string `yaml:"-"`
}

type ProviderConfig struct {
	Name      string       `yaml:"name"`
	TargetDir string       `yaml:"target_dir"`
	Files     []RemoteFile `yaml:"-"`
}

type RemoteFile struct {
	Name  string `yaml:"name"`
	Group string `yaml:"group,omitempty"`
	URL   string `yaml:"url"`
}

func (c *CustomConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawCustomConfig struct {
		TargetDir string    `yaml:"target_dir"`
		Groups    yaml.Node `yaml:"groups"`
	}

	if isZeroYAMLNode(*node) {
		return nil
	}
	if err := ensureAllowedYAMLKeys(*node, map[string]struct{}{
		"target_dir": {},
		"groups":     {},
	}); err != nil {
		return err
	}

	var raw rawCustomConfig
	if err := node.Decode(&raw); err != nil {
		return err
	}

	groups, err := decodeCustomGroupsNode(raw.Groups)
	if err != nil {
		return fmt.Errorf("decode custom groups: %w", err)
	}

	c.TargetDir = raw.TargetDir
	c.Groups = groups
	return nil
}

func (p *ProviderConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawProviderConfig struct {
		Name      string    `yaml:"name"`
		TargetDir string    `yaml:"target_dir"`
		Files     yaml.Node `yaml:"files"`
		Groups    yaml.Node `yaml:"groups"`
	}

	var raw rawProviderConfig
	if err := ensureAllowedYAMLKeys(*node, map[string]struct{}{
		"name":       {},
		"target_dir": {},
		"files":      {},
		"groups":     {},
	}); err != nil {
		return err
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}

	files, err := decodeProviderFilesNode(raw.Files, "")
	if err != nil {
		return fmt.Errorf("decode provider files: %w", err)
	}
	groupFiles, err := decodeProviderGroupsNode(raw.Groups)
	if err != nil {
		return fmt.Errorf("decode provider groups: %w", err)
	}

	p.Name = raw.Name
	p.TargetDir = raw.TargetDir
	p.Files = append(files, groupFiles...)
	return nil
}

type payloadFile struct {
	Payload []string `yaml:"payload"`
}

type rawEntryKind int

const (
	rawEntryRule rawEntryKind = iota
	rawEntryInclude
)

type rawEntry struct {
	Kind    rawEntryKind
	Rule    string
	Include string
	Attrs   map[string]bool
	Filters attrFilters
}

type attrFilters struct {
	Require map[string]bool
	Exclude map[string]bool
}

type resolvedRule struct {
	Rule  string
	Attrs map[string]bool
}

type sourcedRule struct {
	Rule   string
	Source string
	Group  string
}

type groupedValue struct {
	Value   string
	Sources []string
}

type ruleFile struct {
	Path  string
	Group string
}

type builder struct {
	client       *http.Client
	stdout       io.Writer
	lookupIPFunc func(context.Context, string) ([]netip.Addr, error)
}

type finalRuleTarget uint8

const (
	finalRuleTargetDomain finalRuleTarget = iota
	finalRuleTargetCIDR
)

type finalOutputData struct {
	DomainRules     []groupedValue
	CIDRRules       []groupedValue
	ResolvableHosts []groupedValue
}

type normalizedFinalRule struct {
	Value          string
	Target         finalRuleTarget
	ResolvableHost string
}

type hostCIDRResult struct {
	Rules []groupedValue
	IPs   int
}

func normalizeOptionalPath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Clean(filepath.FromSlash(path))
}

func normalizeRuleGroup(group string) string {
	group = strings.TrimSpace(strings.ToLower(group))
	if group == "" {
		return defaultRuleGroup
	}
	return group
}

func isSafeRuleGroup(group string) bool {
	group = normalizeRuleGroup(group)
	if group == "" {
		return false
	}

	for _, r := range group {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		case r == '_':
		default:
			return false
		}
	}

	return true
}

func groupOutputPath(basePath, group string) string {
	group = normalizeRuleGroup(group)

	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)
	if dir == "." || dir == "" {
		return filepath.Join(group, base)
	}

	return filepath.Join(dir, group, base)
}

func sortedRuleGroups(data map[string]finalOutputData) []string {
	groups := make([]string, 0, len(data))
	for group := range data {
		groups = append(groups, group)
	}
	sort.Strings(groups)

	if len(groups) == 0 || groups[0] == defaultRuleGroup {
		return groups
	}

	for i, group := range groups {
		if group != defaultRuleGroup {
			continue
		}
		copy(groups[1:i+1], groups[0:i])
		groups[0] = defaultRuleGroup
		break
	}

	return groups
}

func splitRuleTypeValue(rule string) (string, string, bool) {
	ruleType, value, ok := strings.Cut(strings.TrimSpace(rule), ",")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(ruleType), strings.TrimSpace(value), true
}

func Run(opts Options) error {
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	baseOutputPath := resolveOutputPath(cfg.Build, opts)

	b := builder{
		client: &http.Client{Timeout: 60 * time.Second},
		stdout: opts.Stdout,
	}
	generatedAt := time.Now()

	if !opts.SkipDownload {
		if err := b.downloadProviders(cfg); err != nil {
			return err
		}
	} else {
		b.printf("skip download: using local provider files\n")
	}

	if err := b.convertProviders(cfg); err != nil {
		return err
	}

	outputDataByGroup, err := b.collectCombinedRules(cfg)
	if err != nil {
		return err
	}

	for _, group := range sortedRuleGroups(outputDataByGroup) {
		outputData := outputDataByGroup[group]
		finalCIDRRules := uniqueGroupedValues(outputData.CIDRRules)
		if shouldDeriveCIDR(cfg.Build, opts) {
			derivedCIDRRules, err := b.deriveCIDRRulesFromDomains(outputData.ResolvableHosts)
			if err != nil {
				return err
			}
			finalCIDRRules = uniqueGroupedValues(append(finalCIDRRules, derivedCIDRRules...))
			b.printf("derived %d CIDR rules from %d domains for group %s\n", len(derivedCIDRRules), len(outputData.ResolvableHosts), group)
		}

		finalRules := mergeFinalRules(finalCIDRRules, outputData.DomainRules)
		outputPath := groupOutputPath(baseOutputPath, group)

		if err := writeGroupedPayloadFile(outputPath, finalRules, group+" ruleset", true, generatedAt); err != nil {
			return err
		}

		b.printf("wrote %s (%d rules)\n", outputPath, len(finalRules))
	}
	return nil
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	for i := range cfg.Providers {
		cfg.Providers[i].TargetDir = normalizeOptionalPath(cfg.Providers[i].TargetDir)
		for j := range cfg.Providers[i].Files {
			cfg.Providers[i].Files[j].Group = normalizeRuleGroup(cfg.Providers[i].Files[j].Group)
		}
	}
	cfg.Custom = normalizeCustomConfig(cfg.Custom)
	cfg.Build = normalizeBuildConfigPaths(cfg.Build)

	return cfg, nil
}

func normalizeCustomConfig(cfg CustomConfig) CustomConfig {
	cfg.TargetDir = normalizeOptionalPath(cfg.TargetDir)
	if len(cfg.Groups) == 0 {
		return cfg
	}

	normalizedGroups := make(map[string][]string, len(cfg.Groups))
	for group, files := range cfg.Groups {
		group = normalizeRuleGroup(group)
		normalizedGroups[group] = append(normalizedGroups[group], files...)
	}
	cfg.Groups = normalizedGroups
	return cfg
}

func decodeProviderGroupsNode(node yaml.Node) ([]RemoteFile, error) {
	if isZeroYAMLNode(node) {
		return nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node, got %v", node.Kind)
	}

	files := make([]RemoteFile, 0, len(node.Content))
	for i := 0; i+1 < len(node.Content); i += 2 {
		group := strings.TrimSpace(node.Content[i].Value)
		groupFiles, err := decodeProviderFilesNode(*node.Content[i+1], group)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", group, err)
		}
		files = append(files, groupFiles...)
	}

	return files, nil
}

func decodeCustomGroupsNode(node yaml.Node) (map[string][]string, error) {
	if isZeroYAMLNode(node) {
		return nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node, got %v", node.Kind)
	}

	var groups map[string][]string
	if err := node.Decode(&groups); err != nil {
		return nil, err
	}

	return groups, nil
}

func decodeProviderFilesNode(node yaml.Node, defaultGroup string) ([]RemoteFile, error) {
	if isZeroYAMLNode(node) {
		return nil, nil
	}

	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node, got %v", node.Kind)
	}

	files := make([]RemoteFile, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		nameNode := node.Content[i]
		urlNode := node.Content[i+1]
		if urlNode.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("file %q must map to scalar url", nameNode.Value)
		}
		files = append(files, RemoteFile{
			Name:  strings.TrimSpace(nameNode.Value),
			Group: defaultGroup,
			URL:   strings.TrimSpace(urlNode.Value),
		})
	}
	return files, nil
}

func isZeroYAMLNode(node yaml.Node) bool {
	return node.Kind == 0 && node.Tag == "" && node.Value == "" && len(node.Content) == 0
}

func ensureAllowedYAMLKeys(node yaml.Node, allowed map[string]struct{}) error {
	if isZeroYAMLNode(node) {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node, got %v", node.Kind)
	}

	for i := 0; i+1 < len(node.Content); i += 2 {
		key := strings.TrimSpace(node.Content[i].Value)
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unsupported field %q", key)
		}
	}

	return nil
}

func validateConfig(cfg Config) error {
	seenProviders := map[string]struct{}{}
	for i, provider := range cfg.Providers {
		if strings.TrimSpace(provider.Name) == "" {
			return fmt.Errorf("provider[%d] has empty name", i)
		}
		if _, exists := seenProviders[provider.Name]; exists {
			return fmt.Errorf("duplicate provider name %q", provider.Name)
		}
		seenProviders[provider.Name] = struct{}{}

		if provider.TargetDir == "" {
			return fmt.Errorf("provider %q has empty target_dir", provider.Name)
		}

		seenFiles := map[string]struct{}{}
		for _, file := range provider.Files {
			if file.Name == "" || file.URL == "" {
				return fmt.Errorf("provider %q has invalid file entry: %+v", provider.Name, file)
			}
			if filepath.Clean(file.Name) != filepath.Base(file.Name) {
				return fmt.Errorf("provider %q has unsafe file name %q", provider.Name, file.Name)
			}
			if !isSafeRuleGroup(file.Group) {
				return fmt.Errorf("provider %q file %q has unsafe group %q", provider.Name, file.Name, file.Group)
			}
			if _, exists := seenFiles[file.Name]; exists {
				return fmt.Errorf("provider %q has duplicate file %q", provider.Name, file.Name)
			}
			seenFiles[file.Name] = struct{}{}
		}
	}

	if cfg.Custom.TargetDir != "" && len(cfg.Custom.Groups) == 0 {
		return errors.New("custom has target_dir but no groups")
	}
	if len(cfg.Custom.Groups) > 0 && cfg.Custom.TargetDir == "" {
		return errors.New("custom has empty target_dir")
	}

	seenCustomFiles := map[string]struct{}{}
	for group, files := range cfg.Custom.Groups {
		for _, fileName := range files {
			fileName = strings.TrimSpace(fileName)
			if fileName == "" {
				return fmt.Errorf("custom group %q has empty file entry", group)
			}
			if filepath.Clean(fileName) != filepath.Base(fileName) {
				return fmt.Errorf("custom has unsafe file name %q", fileName)
			}
			if !isSafeRuleGroup(group) {
				return fmt.Errorf("custom group has unsafe name %q", group)
			}
			if _, exists := seenCustomFiles[fileName]; exists {
				return fmt.Errorf("custom has duplicate file %q", fileName)
			}
			seenCustomFiles[fileName] = struct{}{}
		}
	}

	return nil
}

func shouldDeriveCIDR(build BuildConfig, opts Options) bool {
	return build.DeriveCIDR || opts.DeriveCIDR
}

func normalizeBuildConfigPaths(build BuildConfig) BuildConfig {
	build.Output = normalizeOptionalPath(build.Output)
	return build
}

func resolveOutputPath(build BuildConfig, opts Options) string {
	build = normalizeBuildConfigPaths(build)

	outputPath := build.Output
	if outputPath == "" {
		outputPath = defaultOutputPath
	}
	if opts.OutputPath != "" {
		outputPath = normalizeOptionalPath(opts.OutputPath)
	}

	return outputPath
}

func (b builder) downloadProviders(cfg Config) error {
	for _, provider := range cfg.Providers {
		if err := os.MkdirAll(provider.TargetDir, 0o755); err != nil {
			return fmt.Errorf("create provider dir %s: %w", provider.TargetDir, err)
		}

		for _, file := range provider.Files {
			destPath := filepath.Join(provider.TargetDir, file.Name)
			b.printf("download %s/%s\n", provider.Name, file.Name)
			if err := b.downloadFile(file.URL, destPath); err != nil {
				return fmt.Errorf("download %s/%s: %w", provider.Name, file.Name, err)
			}
		}
	}

	return nil
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (b builder) downloadFile(rawURL, destPath string) error {
	downloadURL, err := normalizeGitHubRawURL(rawURL)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mihomo_rules/1.0")

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return errors.New("downloaded empty file")
	}
	if isLikelyHTML(body) {
		return errors.New("downloaded HTML instead of raw content")
	}

	return writeFileAtomically(destPath, body)
}

func replaceFileFromTemp(tmpPath, destPath string) error {
	if _, err := os.Stat(destPath); errors.Is(err, os.ErrNotExist) {
		return os.Rename(tmpPath, destPath)
	} else if err != nil {
		return err
	}

	backupPath := destPath + ".bak"
	if err := removeIfExists(backupPath); err != nil {
		return err
	}
	if err := os.Rename(destPath, backupPath); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		restoreErr := os.Rename(backupPath, destPath)
		if restoreErr != nil {
			return fmt.Errorf("replace %s: rename failed: %w; restore failed: %v", destPath, err, restoreErr)
		}
		return err
	}

	if err := removeIfExists(backupPath); err != nil {
		return err
	}

	return nil
}

func normalizeGitHubRawURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse URL %q: %w", rawURL, err)
	}

	if !strings.EqualFold(parsed.Host, "github.com") {
		return rawURL, nil
	}

	parts := splitURLPath(parsed.Path)
	if len(parts) < 5 || parts[2] != "blob" {
		return rawURL, nil
	}

	rawParts := append([]string{parts[0], parts[1], parts[3]}, parts[4:]...)
	parsed.Scheme = "https"
	parsed.Host = "raw.githubusercontent.com"
	parsed.Path = "/" + strings.Join(rawParts, "/")
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String(), nil
}

func splitURLPath(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}

func isLikelyHTML(body []byte) bool {
	trimmed := strings.ToLower(string(bytes.TrimSpace(body)))
	return strings.HasPrefix(trimmed, "<!doctype html") || strings.HasPrefix(trimmed, "<html")
}

func (b builder) convertProviders(cfg Config) error {
	for _, provider := range cfg.Providers {
		for _, file := range provider.Files {
			sourcePath := filepath.Join(provider.TargetDir, file.Name)
			if err := b.convertProviderFile(provider.Name, sourcePath); err != nil {
				return err
			}
		}
	}

	return nil
}

func providerRuleLabel(providerName, path string) string {
	return providerName + "/" + filepath.Base(path)
}

func (b builder) convertProviderFile(providerName, sourcePath string) error {
	switch strings.ToLower(filepath.Ext(sourcePath)) {
	case ".raw":
		rules, err := parseRawFile(sourcePath)
		if err != nil {
			return fmt.Errorf("convert %s: %w", sourcePath, err)
		}

		outputPath := strings.TrimSuffix(sourcePath, filepath.Ext(sourcePath)) + ".mihomo"
		if err := writePayloadFile(outputPath, rules, providerRuleLabel(providerName, outputPath), false); err != nil {
			return err
		}
		b.printf("generated %s (%d rules)\n", outputPath, len(rules))
	case ".mihomo":
		rules, _, err := parseRuleFile(sourcePath)
		if err != nil {
			return fmt.Errorf("normalize %s: %w", sourcePath, err)
		}

		if err := writePayloadFile(sourcePath, rules, providerRuleLabel(providerName, sourcePath), false); err != nil {
			return err
		}
		b.printf("normalized %s (%d rules)\n", sourcePath, len(rules))
	}

	return nil
}

func parseRawFile(path string) ([]string, error) {
	cache := map[string][]resolvedRule{}
	rules, err := parseRawFileWithState(path, cache, map[string]bool{})
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.Rule)
	}

	return out, nil
}

func parseRawFileWithState(path string, cache map[string][]resolvedRule, visiting map[string]bool) ([]resolvedRule, error) {
	path = filepath.Clean(path)
	if cached, ok := cache[path]; ok {
		return cloneResolvedRules(cached), nil
	}
	if visiting[path] {
		return nil, fmt.Errorf("cyclic include detected for %s", path)
	}

	visiting[path] = true
	defer delete(visiting, path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if isLikelyHTML(data) {
		return nil, errors.New("raw file contains HTML instead of rules")
	}

	entries, err := parseRawEntries(data)
	if err != nil {
		return nil, err
	}

	resolved := make([]resolvedRule, 0, len(entries))
	for _, entry := range entries {
		switch entry.Kind {
		case rawEntryRule:
			resolved = append(resolved, resolvedRule{
				Rule:  entry.Rule,
				Attrs: cloneAttrs(entry.Attrs),
			})
		case rawEntryInclude:
			includePath, err := resolveIncludePath(path, entry.Include)
			if err != nil {
				return nil, err
			}
			includeRules, err := parseRawFileWithState(includePath, cache, visiting)
			if err != nil {
				return nil, err
			}
			for _, includeRule := range includeRules {
				if entry.Filters.Match(includeRule.Attrs) {
					resolved = append(resolved, includeRule)
				}
			}
		default:
			return nil, fmt.Errorf("unsupported raw entry kind in %s", path)
		}
	}

	cache[path] = cloneResolvedRules(resolved)
	return resolved, nil
}

func cloneResolvedRules(rules []resolvedRule) []resolvedRule {
	cloned := make([]resolvedRule, len(rules))
	for i, rule := range rules {
		cloned[i] = resolvedRule{
			Rule:  rule.Rule,
			Attrs: cloneAttrs(rule.Attrs),
		}
	}
	return cloned
}

func cloneAttrs(attrs map[string]bool) map[string]bool {
	if len(attrs) == 0 {
		return nil
	}
	cloned := make(map[string]bool, len(attrs))
	for key, value := range attrs {
		cloned[key] = value
	}
	return cloned
}

func resolveIncludePath(currentPath, includeName string) (string, error) {
	dir := filepath.Dir(currentPath)
	candidates := []string{
		filepath.Join(dir, includeName),
		filepath.Join(dir, includeName+".raw"),
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	needle := strings.ToLower(includeName)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		base := strings.TrimSuffix(name, filepath.Ext(name))
		if strings.EqualFold(base, needle) {
			return filepath.Join(dir, name), nil
		}
	}

	return "", fmt.Errorf("include %q referenced from %s was not found locally", includeName, currentPath)
}

func parseRawEntries(data []byte) ([]rawEntry, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	entries := make([]rawEntry, 0)
	for scanner.Scan() {
		line := normalizeRawLine(scanner.Text())
		if line == "" {
			continue
		}

		entry, err := parseRawEntry(line)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func normalizeRawLine(line string) string {
	line = strings.TrimSpace(stripTrailingComment(line))
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	return line
}

func stripTrailingComment(line string) string {
	for i, r := range line {
		if r == '#' {
			if i == 0 {
				return ""
			}
			prev := rune(line[i-1])
			if unicode.IsSpace(prev) {
				return line[:i]
			}
		}
	}
	return line
}

func parseRawEntry(line string) (rawEntry, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return rawEntry{}, errors.New("empty raw line")
	}

	head := parts[0]
	tail := parts[1:]

	if strings.HasPrefix(head, "include:") {
		filters, err := parseIncludeFilters(tail)
		if err != nil {
			return rawEntry{}, err
		}
		return rawEntry{
			Kind:    rawEntryInclude,
			Include: strings.TrimPrefix(head, "include:"),
			Filters: filters,
		}, nil
	}

	attrs, err := parseEntryAttrs(tail)
	if err != nil {
		return rawEntry{}, err
	}

	rule, err := rawTokenToRule(head)
	if err != nil {
		return rawEntry{}, err
	}

	return rawEntry{
		Kind:  rawEntryRule,
		Rule:  rule,
		Attrs: attrs,
	}, nil
}

func parseIncludeFilters(tokens []string) (attrFilters, error) {
	filters := attrFilters{
		Require: map[string]bool{},
		Exclude: map[string]bool{},
	}

	for _, token := range tokens {
		switch {
		case strings.HasPrefix(token, "@-"):
			name := strings.TrimPrefix(token, "@-")
			if name == "" {
				return attrFilters{}, fmt.Errorf("invalid include filter %q", token)
			}
			filters.Exclude[name] = true
		case strings.HasPrefix(token, "@"):
			name := strings.TrimPrefix(token, "@")
			if name == "" {
				return attrFilters{}, fmt.Errorf("invalid include filter %q", token)
			}
			filters.Require[name] = true
		case strings.HasPrefix(token, "&"):
			continue
		default:
			return attrFilters{}, fmt.Errorf("unsupported include filter token %q", token)
		}
	}

	return filters, nil
}

func parseEntryAttrs(tokens []string) (map[string]bool, error) {
	if len(tokens) == 0 {
		return nil, nil
	}

	attrs := map[string]bool{}
	for _, token := range tokens {
		switch {
		case strings.HasPrefix(token, "@"):
			name := strings.TrimPrefix(token, "@")
			if name == "" || strings.HasPrefix(name, "-") {
				return nil, fmt.Errorf("invalid rule attribute %q", token)
			}
			attrs[name] = true
		case strings.HasPrefix(token, "&"):
			continue
		default:
			return nil, fmt.Errorf("unsupported raw token %q", token)
		}
	}

	return attrs, nil
}

func (f attrFilters) Match(attrs map[string]bool) bool {
	for required := range f.Require {
		if !attrs[required] {
			return false
		}
	}
	for excluded := range f.Exclude {
		if attrs[excluded] {
			return false
		}
	}
	return true
}

func rawTokenToRule(token string) (string, error) {
	if isClassicalRule(token) {
		return token, nil
	}

	switch {
	case strings.HasPrefix(token, "full:"):
		return "DOMAIN," + strings.TrimPrefix(token, "full:"), nil
	case strings.HasPrefix(token, "domain:"):
		return "DOMAIN-SUFFIX," + strings.TrimPrefix(token, "domain:"), nil
	case strings.HasPrefix(token, "keyword:"):
		return "DOMAIN-KEYWORD," + strings.TrimPrefix(token, "keyword:"), nil
	case strings.HasPrefix(token, "regexp:"):
		return "DOMAIN-REGEX," + strings.TrimPrefix(token, "regexp:"), nil
	case strings.HasPrefix(token, "include:"):
		return "", errors.New("include token must be handled separately")
	case strings.HasPrefix(token, "geosite:"):
		return "", fmt.Errorf("unsupported geosite reference %q", token)
	}

	if prefix, err := netip.ParsePrefix(token); err == nil {
		if prefix.Addr().Is6() {
			return "IP-CIDR6," + prefix.String(), nil
		}
		return "IP-CIDR," + prefix.String(), nil
	}

	if addr, err := netip.ParseAddr(token); err == nil {
		if addr.Is6() {
			return "IP-CIDR6," + addr.String() + "/128", nil
		}
		return "IP-CIDR," + addr.String() + "/32", nil
	}

	if token == "" {
		return "", errors.New("empty rule token")
	}

	return "DOMAIN-SUFFIX," + token, nil
}

func isClassicalRule(rule string) bool {
	ruleType, _, ok := splitRuleTypeValue(rule)
	if !ok {
		return false
	}
	_, exists := classicalRuleTypes[ruleType]
	return exists
}

func parseRuleFile(path string) ([]string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	rules, isPayload, err := parsePayloadYAML(data)
	if err != nil {
		return nil, false, err
	}
	if isPayload {
		return rules, true, nil
	}

	rules, err = parsePlainRuleLines(data)
	return rules, false, err
}

func parsePayloadYAML(data []byte) ([]string, bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, nil
	}
	if len(doc.Content) == 0 {
		return nil, false, nil
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, false, nil
	}

	for i := 0; i+1 < len(root.Content); i += 2 {
		keyNode := root.Content[i]
		valueNode := root.Content[i+1]
		if strings.TrimSpace(keyNode.Value) != "payload" {
			continue
		}

		var payload payloadFile
		if err := valueNode.Decode(&payload.Payload); err != nil {
			return nil, false, fmt.Errorf("decode payload YAML: %w", err)
		}
		return cleanRules(payload.Payload), true, nil
	}

	return nil, false, nil
}

func parsePlainRuleLines(data []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	rules := make([]string, 0)
	for scanner.Scan() {
		line := normalizeRawLine(scanner.Text())
		if line == "" || line == "payload:" {
			continue
		}
		rule, err := rawTokenToRule(line)
		if err != nil {
			return nil, fmt.Errorf("parse rule line %q: %w", line, err)
		}
		rules = append(rules, rule)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

func cleanRules(rules []string) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueGroupedValues(values []groupedValue) []groupedValue {
	seen := make(map[string]int, len(values))
	out := make([]groupedValue, 0, len(values))

	for _, value := range values {
		value.Value = strings.TrimSpace(value.Value)
		if value.Value == "" {
			continue
		}
		value.Sources = uniqueStrings(value.Sources)

		if idx, exists := seen[value.Value]; exists {
			out[idx].Sources = uniqueStrings(append(out[idx].Sources, value.Sources...))
			continue
		}

		seen[value.Value] = len(out)
		out = append(out, value)
	}

	return out
}

func groupedValueFromSource(value, source string) groupedValue {
	return groupedValue{
		Value:   value,
		Sources: []string{source},
	}
}

func (d *finalOutputData) addRule(rule normalizedFinalRule, source string) {
	switch rule.Target {
	case finalRuleTargetDomain:
		d.DomainRules = append(d.DomainRules, groupedValueFromSource(rule.Value, source))
		if rule.ResolvableHost != "" {
			d.ResolvableHosts = append(d.ResolvableHosts, groupedValueFromSource(rule.ResolvableHost, source))
		}
	case finalRuleTargetCIDR:
		d.CIDRRules = append(d.CIDRRules, groupedValueFromSource(rule.Value, source))
	}
}

func (d *finalOutputData) finalize() {
	d.DomainRules = uniqueGroupedValues(d.DomainRules)
	d.DomainRules = filterDomainRulesCoveredByZoneSuffixes(d.DomainRules)
	d.CIDRRules = uniqueGroupedValues(d.CIDRRules)
	d.ResolvableHosts = uniqueGroupedValues(d.ResolvableHosts)
}

func (b builder) collectCombinedRules(cfg Config) (map[string]finalOutputData, error) {
	combined, err := collectSourcedRules(cfg)
	if err != nil {
		return nil, err
	}

	return splitRulesForFinalOutput(combined)
}

func collectSourcedRules(cfg Config) ([]sourcedRule, error) {
	files, err := collectRuleFiles(cfg)
	if err != nil {
		return nil, err
	}

	combined := make([]sourcedRule, 0)
	for _, file := range files {
		rules, _, err := parseRuleFile(file.Path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file.Path, err)
		}
		combined = append(combined, sourceRules(filepath.ToSlash(file.Path), file.Group, rules)...)
	}

	return combined, nil
}

func sourceRules(source, group string, rules []string) []sourcedRule {
	sourced := make([]sourcedRule, 0, len(rules))
	for _, rule := range rules {
		sourced = append(sourced, sourcedRule{
			Rule:   rule,
			Source: source,
			Group:  normalizeRuleGroup(group),
		})
	}
	return sourced
}

func splitRulesForFinalOutput(rules []sourcedRule) (map[string]finalOutputData, error) {
	dataByGroup := make(map[string]finalOutputData)
	for _, rule := range rules {
		normalizedRule, err := normalizeRuleForFinalOutput(rule.Rule)
		if err != nil {
			return nil, err
		}
		group := normalizeRuleGroup(rule.Group)
		data := dataByGroup[group]
		data.addRule(normalizedRule, rule.Source)
		dataByGroup[group] = data
	}

	if len(dataByGroup) == 0 {
		dataByGroup[defaultRuleGroup] = finalOutputData{}
	}

	for group, data := range dataByGroup {
		data.finalize()
		dataByGroup[group] = data
	}

	return dataByGroup, nil
}

func mergeFinalRules(cidrRules, domainRules []groupedValue) []groupedValue {
	merged := make([]groupedValue, 0, len(cidrRules)+len(domainRules))
	merged = append(merged, domainRules...)
	merged = append(merged, cidrRules...)
	return merged
}

func filterDomainRulesCoveredByZoneSuffixes(rules []groupedValue) []groupedValue {
	zoneSuffixes := make([]string, 0)
	for _, rule := range rules {
		ruleType, value, ok := splitRuleTypeValue(rule.Value)
		if !ok {
			continue
		}
		if ruleType == "DOMAIN-SUFFIX" && isWholeZoneSuffix(value) {
			zoneSuffixes = append(zoneSuffixes, value)
		}
	}
	zoneSuffixes = uniqueStrings(zoneSuffixes)

	filtered := make([]groupedValue, 0, len(rules))
	for _, rule := range rules {
		ruleType, value, ok := splitRuleTypeValue(rule.Value)
		if !ok {
			filtered = append(filtered, rule)
			continue
		}

		if ruleType == "DOMAIN-SUFFIX" && !isWholeZoneSuffix(value) && isCoveredByZoneSuffix(value, zoneSuffixes) {
			continue
		}

		filtered = append(filtered, rule)
	}

	return filtered
}

func isCoveredByZoneSuffix(value string, zoneSuffixes []string) bool {
	for _, zone := range zoneSuffixes {
		if strings.EqualFold(value, zone) {
			return true
		}
		if strings.HasSuffix(strings.ToLower(value), "."+strings.ToLower(zone)) {
			return true
		}
	}
	return false
}

func effectiveTLDPlusTwo(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty domain")
	}

	root, err := publicsuffix.EffectiveTLDPlusOne(value)
	if err != nil || root == "" {
		return "", err
	}

	rootLabels := strings.Split(root, ".")
	valueLabels := strings.Split(value, ".")
	if len(valueLabels) <= len(rootLabels) {
		return root, nil
	}

	return strings.Join(valueLabels[len(valueLabels)-len(rootLabels)-1:], "."), nil
}

func normalizeRuleForFinalOutput(rule string) (normalizedFinalRule, error) {
	ruleType, value, ok := splitRuleTypeValue(rule)
	if !ok {
		return normalizedFinalRule{}, fmt.Errorf("invalid rule %q", rule)
	}
	if value == "" {
		return normalizedFinalRule{}, fmt.Errorf("invalid rule %q: empty value", rule)
	}

	switch ruleType {
	case "DOMAIN", "DOMAIN-SUFFIX":
		return normalizeDomainRuleForFinalOutput(value), nil
	case "DOMAIN-KEYWORD", "DOMAIN-REGEX":
		return normalizedFinalRule{
			Value:  ruleType + "," + value,
			Target: finalRuleTargetDomain,
		}, nil
	case "IP-ASN", "IP-CIDR", "IP-CIDR6":
		return normalizedFinalRule{
			Value:  addNoResolveOption(ruleType, value),
			Target: finalRuleTargetCIDR,
		}, nil
	default:
		return normalizedFinalRule{}, fmt.Errorf("unsupported final rule type %q", ruleType)
	}
}

func normalizeDomainRuleForFinalOutput(value string) normalizedFinalRule {
	normalized := normalizedFinalRule{
		Value:          "DOMAIN-SUFFIX," + value,
		Target:         finalRuleTargetDomain,
		ResolvableHost: value,
	}
	if isWholeZoneSuffix(value) {
		normalized.ResolvableHost = ""
		return normalized
	}

	root, err := effectiveTLDPlusTwo(value)
	if err != nil || root == "" {
		return normalized
	}

	normalized.Value = "DOMAIN-SUFFIX," + root
	return normalized
}

func addNoResolveOption(ruleType, value string) string {
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	if len(parts) == 0 || parts[0] == "" {
		return ruleType + "," + strings.TrimSpace(value)
	}

	for _, part := range parts[1:] {
		if strings.EqualFold(part, "no-resolve") {
			return ruleType + "," + strings.Join(parts, ",")
		}
	}

	parts = append(parts, "no-resolve")
	return ruleType + "," + strings.Join(parts, ",")
}

func isWholeZoneSuffix(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	suffix, _ := publicsuffix.PublicSuffix(value)
	return strings.EqualFold(suffix, value)
}

func (b builder) deriveCIDRRulesFromDomains(hosts []groupedValue) ([]groupedValue, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	jobs := make(chan groupedValue)
	results := make(chan hostCIDRResult, len(hosts))

	workerCount := minInt(dnsLookupWorkers, len(hosts))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				results <- b.deriveCIDRRulesForHost(host)
			}
		}()
	}

	for _, host := range hosts {
		jobs <- host
	}
	close(jobs)

	wg.Wait()
	close(results)

	rules, resolvedCount := collectDerivedCIDRResults(results, len(hosts))
	if len(rules) == 0 {
		return nil, nil
	}
	b.printf("resolved %d IPs from %d domains\n", resolvedCount, len(hosts))

	return uniqueGroupedValues(rules), nil
}

func (b builder) deriveCIDRRulesForHost(host groupedValue) hostCIDRResult {
	ips := b.resolveSingleHostToIPs(host.Value)
	if len(ips) == 0 {
		return hostCIDRResult{}
	}

	sources := deriveCIDRSources(host)
	rules := make([]groupedValue, 0, len(ips))
	for _, ip := range ips {
		rules = append(rules, groupedValue{
			Value:   derivedCIDRRuleValue(ip),
			Sources: sources,
		})
	}

	return hostCIDRResult{
		Rules: rules,
		IPs:   len(ips),
	}
}

func collectDerivedCIDRResults(results <-chan hostCIDRResult, capacity int) ([]groupedValue, int) {
	rules := make([]groupedValue, 0, capacity)
	resolvedCount := 0

	for result := range results {
		resolvedCount += result.IPs
		rules = append(rules, result.Rules...)
	}

	return rules, resolvedCount
}

func deriveCIDRSources(host groupedValue) []string {
	sources := make([]string, 0, len(host.Sources))
	for _, source := range host.Sources {
		sources = append(sources, source+" [derived from "+host.Value+"]")
	}
	return sources
}

func derivedCIDRRuleValue(ip netip.Addr) string {
	if ip.Is6() {
		return "IP-CIDR6," + ip.String() + "/128,no-resolve"
	}
	return "IP-CIDR," + netip.PrefixFrom(ip, 24).Masked().String() + ",no-resolve"
}

func (b builder) resolveSingleHostToIPs(host string) []netip.Addr {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}

	lookupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addresses, err := b.lookupDomainIPs(lookupCtx, host)
	if err != nil {
		return nil
	}
	return addresses
}

func uniqueAddrs(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}
		if _, exists := seen[addr]; exists {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func (b builder) lookupDomainIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if b.lookupIPFunc != nil {
		return b.lookupIPFunc(ctx, host)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		addrs = append(addrs, addr.Unmap())
	}
	return uniqueAddrs(addrs), nil
}

func collectRuleFiles(cfg Config) ([]ruleFile, error) {
	providerFiles, err := collectConfiguredProviderRuleFiles(cfg)
	if err != nil {
		return nil, err
	}
	customFiles := collectConfiguredCustomRuleFiles(cfg)
	files := make([]ruleFile, 0, len(providerFiles)+len(customFiles))
	files = append(files, providerFiles...)
	files = append(files, customFiles...)

	sort.Slice(files, func(i, j int) bool {
		if files[i].Path == files[j].Path {
			return files[i].Group < files[j].Group
		}
		return files[i].Path < files[j].Path
	})
	return files, nil
}

func collectConfiguredCustomRuleFiles(cfg Config) []ruleFile {
	if len(cfg.Custom.Groups) == 0 {
		return nil
	}

	groupNames := make([]string, 0, len(cfg.Custom.Groups))
	for group := range cfg.Custom.Groups {
		groupNames = append(groupNames, group)
	}
	sort.Strings(groupNames)

	totalFiles := 0
	for _, files := range cfg.Custom.Groups {
		totalFiles += len(files)
	}

	files := make([]ruleFile, 0, totalFiles)
	seen := map[string]struct{}{}

	for _, group := range groupNames {
		for _, fileName := range cfg.Custom.Groups[group] {
			path := filepath.Join(cfg.Custom.TargetDir, fileName)
			path = filepath.Clean(path)
			if _, exists := seen[path]; exists {
				continue
			}
			seen[path] = struct{}{}
			files = append(files, ruleFile{
				Path:  path,
				Group: normalizeRuleGroup(group),
			})
		}
	}

	return files
}

func collectConfiguredProviderRuleFiles(cfg Config) ([]ruleFile, error) {
	files := make([]ruleFile, 0, len(cfg.Providers))
	seen := map[string]struct{}{}

	for _, provider := range cfg.Providers {
		for _, file := range provider.Files {
			rulePath, err := providerRuleOutputPath(provider.TargetDir, file.Name)
			if err != nil {
				return nil, fmt.Errorf("provider %q file %q: %w", provider.Name, file.Name, err)
			}
			if _, exists := seen[rulePath]; exists {
				continue
			}
			seen[rulePath] = struct{}{}
			files = append(files, ruleFile{
				Path:  rulePath,
				Group: normalizeRuleGroup(file.Group),
			})
		}
	}

	return files, nil
}

func providerRuleOutputPath(targetDir, fileName string) (string, error) {
	path := filepath.Join(targetDir, fileName)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".raw":
		return filepath.Clean(strings.TrimSuffix(path, filepath.Ext(path)) + ".mihomo"), nil
	case ".mihomo", ".yaml", ".yml":
		return filepath.Clean(path), nil
	default:
		return "", fmt.Errorf("unsupported provider file extension %q", filepath.Ext(path))
	}
}

func writePayloadFile(path string, rules []string, label string, dedupe bool) error {
	rules = cleanRules(rules)
	if dedupe {
		rules = uniqueStrings(rules)
	}

	payloadData, err := yaml.Marshal(payloadFile{Payload: rules})
	if err != nil {
		return err
	}

	header := fmt.Sprintf("# Generated by mihomo_rules for %s.\n# DO NOT EDIT.\n", label)
	content := append([]byte(header), payloadData...)

	return writeGeneratedFile(path, content)
}

func writeGroupedPayloadFile(path string, rules []groupedValue, label string, dedupe bool, generatedAt time.Time) error {
	if dedupe {
		rules = uniqueGroupedValues(rules)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Generated by mihomo_rules for %s.\n# DO NOT EDIT.\n", label)
	fmt.Fprintf(&buf, "# Generated at: %s\n", generatedAt.Format(time.RFC3339))
	fmt.Fprintf(&buf, "# Entries: %d\n", len(rules))
	buf.WriteString("payload:\n")

	lastGroupLabel := ""
	for _, rule := range rules {
		rule.Value = strings.TrimSpace(rule.Value)
		if rule.Value == "" {
			continue
		}

		groupLabel := formatGroupedValueSources(rule.Sources)
		if groupLabel != lastGroupLabel {
			fmt.Fprintf(&buf, "    # %s\n", groupLabel)
			lastGroupLabel = groupLabel
		}
		fmt.Fprintf(&buf, "    - %s\n", rule.Value)
	}

	return writeGeneratedFile(path, buf.Bytes())
}

func writeGeneratedFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	return writeFileAtomically(path, content)
}

func writeFileAtomically(path string, content []byte) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o644); err != nil {
		return err
	}
	return replaceFileFromTemp(tmpPath, path)
}

func formatGroupedValueSources(sources []string) string {
	sources = uniqueStrings(sources)
	switch len(sources) {
	case 0:
		return "unknown source"
	case 1:
		return sources[0]
	default:
		return "sources: " + strings.Join(sources, "; ")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (b builder) printf(format string, args ...any) {
	if b.stdout == nil {
		return
	}
	fmt.Fprintf(b.stdout, format, args...)
}
