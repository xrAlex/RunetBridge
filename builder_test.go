package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeGitHubRawURL(t *testing.T) {
	t.Parallel()

	got, err := normalizeGitHubRawURL("https://github.com/v2fly/domain-list-community/blob/master/data/ozon")
	if err != nil {
		t.Fatalf("normalizeGitHubRawURL returned error: %v", err)
	}

	want := "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/ozon"
	if got != want {
		t.Fatalf("unexpected raw URL: got %q want %q", got, want)
	}
}

func TestParseRawFileWithIncludeFilters(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.raw")
	sharedPath := filepath.Join(dir, "shared.raw")

	baseContent := "domain:example.com\ninclude:shared @ru\nfull:only.example\n"
	sharedContent := "ru.example @ru\nus.example @us\nkeyword:video @ru\n"

	if err := os.WriteFile(basePath, []byte(baseContent), 0o644); err != nil {
		t.Fatalf("write base.raw: %v", err)
	}
	if err := os.WriteFile(sharedPath, []byte(sharedContent), 0o644); err != nil {
		t.Fatalf("write shared.raw: %v", err)
	}

	got, err := parseRawFile(basePath)
	if err != nil {
		t.Fatalf("parseRawFile returned error: %v", err)
	}

	want := []string{
		"DOMAIN-SUFFIX,example.com",
		"DOMAIN-SUFFIX,ru.example",
		"DOMAIN-KEYWORD,video",
		"DOMAIN,only.example",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected parsed rules:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseRuleFilePlainLines(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "rules.mihomo")
	content := "DOMAIN-SUFFIX,example.com\nIP-CIDR,10.0.0.0/8\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write rules.mihomo: %v", err)
	}

	got, isPayload, err := parseRuleFile(path)
	if err != nil {
		t.Fatalf("parseRuleFile returned error: %v", err)
	}
	if isPayload {
		t.Fatalf("plain line file unexpectedly treated as payload YAML")
	}

	want := []string{
		"DOMAIN-SUFFIX,example.com",
		"IP-CIDR,10.0.0.0/8",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected parsed rules:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseRuleFilePlainLinesSupportsIPASNAndRuleOptions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "rules.mihomo")
	content := "IP-ASN,32590\nIP-CIDR,45.121.184.0/24,no-resolve\nIP-CIDR6,2404:3fc0::/48,no-resolve\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write rules.mihomo: %v", err)
	}

	got, isPayload, err := parseRuleFile(path)
	if err != nil {
		t.Fatalf("parseRuleFile returned error: %v", err)
	}
	if isPayload {
		t.Fatalf("plain line file unexpectedly treated as payload YAML")
	}

	want := []string{
		"IP-ASN,32590",
		"IP-CIDR,45.121.184.0/24,no-resolve",
		"IP-CIDR6,2404:3fc0::/48,no-resolve",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected parsed rules:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseRuleFileDoesNotTreatPayloadWordAsYAML(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "rules.mihomo")
	content := "# payload:\nDOMAIN-REGEX,^payload:.*$\nDOMAIN-SUFFIX,example.com\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write rules.mihomo: %v", err)
	}

	got, isPayload, err := parseRuleFile(path)
	if err != nil {
		t.Fatalf("parseRuleFile returned error: %v", err)
	}
	if isPayload {
		t.Fatalf("plain line file unexpectedly treated as payload YAML")
	}

	want := []string{
		"DOMAIN-REGEX,^payload:.*$",
		"DOMAIN-SUFFIX,example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected parsed rules:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestReplaceFileFromTempReplacesExistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	destPath := filepath.Join(dir, "rules.txt")
	tmpPath := destPath + ".tmp"

	if err := os.WriteFile(destPath, []byte("old"), 0o644); err != nil {
		t.Fatalf("write dest file: %v", err)
	}
	if err := os.WriteFile(tmpPath, []byte("new"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if err := replaceFileFromTemp(tmpPath, destPath); err != nil {
		t.Fatalf("replaceFileFromTemp returned error: %v", err)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read dest file: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("unexpected dest contents: got %q want %q", string(data), "new")
	}

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temp file still exists or stat failed: %v", err)
	}

	if _, err := os.Stat(destPath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("backup file still exists or stat failed: %v", err)
	}
}

func TestConvertProvidersPreservesDuplicatesInMihomoFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	providerDir := filepath.Join(dir, "providers")
	if err := os.MkdirAll(providerDir, 0o755); err != nil {
		t.Fatalf("create provider dir: %v", err)
	}

	path := filepath.Join(providerDir, "sample.mihomo")
	content := "payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,api.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write sample.mihomo: %v", err)
	}

	b := builder{}
	cfg := Config{
		Providers: []ProviderConfig{
			{
				Name:      "test",
				TargetDir: providerDir,
				Files: []RemoteFile{
					{Name: "sample.mihomo"},
				},
			},
		},
	}

	if err := b.convertProviders(cfg); err != nil {
		t.Fatalf("convertProviders returned error: %v", err)
	}

	rules, isPayload, err := parseRuleFile(path)
	if err != nil {
		t.Fatalf("parseRuleFile returned error: %v", err)
	}
	if !isPayload {
		t.Fatalf("normalized file is not payload YAML")
	}

	want := []string{
		"DOMAIN-SUFFIX,example.com",
		"DOMAIN-SUFFIX,example.com",
		"DOMAIN,api.example.com",
	}

	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("unexpected rules after normalization:\n got: %#v\nwant: %#v", rules, want)
	}
}

func TestWritePayloadFileDeduplicatesOnlyWhenRequested(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "final.mihomo")

	rules := []string{
		"DOMAIN-SUFFIX,example.com",
		"DOMAIN-SUFFIX,example.com",
		"DOMAIN,api.example.com",
	}

	if err := writePayloadFile(path, rules, "test", true); err != nil {
		t.Fatalf("writePayloadFile returned error: %v", err)
	}

	got, isPayload, err := parseRuleFile(path)
	if err != nil {
		t.Fatalf("parseRuleFile returned error: %v", err)
	}
	if !isPayload {
		t.Fatalf("written file is not payload YAML")
	}

	want := []string{
		"DOMAIN-SUFFIX,example.com",
		"DOMAIN,api.example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected rules after final write:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestWriteGroupedPayloadFileAddsSourceComments(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "final.yaml")
	generatedAt := time.Date(2026, time.March, 18, 15, 4, 5, 0, time.FixedZone("MSK", 3*60*60))
	rules := []groupedValue{
		{Value: "DOMAIN-SUFFIX,ru", Sources: []string{"custom/default.yaml"}},
		{Value: "DOMAIN-SUFFIX,live.com", Sources: []string{"providers/blackmatrix7/Xbox.mihomo"}},
		{Value: "DOMAIN-SUFFIX,msauth.net", Sources: []string{"providers/blackmatrix7/Xbox.mihomo"}},
	}

	if err := writeGroupedPayloadFile(path, rules, "test", true, generatedAt); err != nil {
		t.Fatalf("writeGroupedPayloadFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read final.yaml: %v", err)
	}

	content := string(data)
	for _, fragment := range []string{
		"# Generated at: 2026-03-18T15:04:05+03:00\n",
		"# Entries: 3\n",
		"payload:\n",
		"    # custom/default.yaml\n",
		"    - DOMAIN-SUFFIX,ru\n",
		"    # providers/blackmatrix7/Xbox.mihomo\n",
		"    - DOMAIN-SUFFIX,live.com\n",
		"    - DOMAIN-SUFFIX,msauth.net\n",
	} {
		if !strings.Contains(content, fragment) {
			t.Fatalf("grouped payload file is missing %q:\n%s", fragment, content)
		}
	}
}

func TestNormalizeRuleForFinalOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule string
		want normalizedFinalRule
	}{
		{
			name: "keeps whole zone suffix as non-resolvable domain rule",
			rule: "DOMAIN-SUFFIX,ru",
			want: normalizedFinalRule{
				Value:  "DOMAIN-SUFFIX,ru",
				Target: finalRuleTargetDomain,
			},
		},
		{
			name: "normalizes host domain to suffix and preserves lookup host",
			rule: "DOMAIN,login.live.com",
			want: normalizedFinalRule{
				Value:          "DOMAIN-SUFFIX,login.live.com",
				Target:         finalRuleTargetDomain,
				ResolvableHost: "login.live.com",
			},
		},
		{
			name: "adds no-resolve to cidr rule",
			rule: "IP-CIDR,10.0.0.0/8",
			want: normalizedFinalRule{
				Value:  "IP-CIDR,10.0.0.0/8,no-resolve",
				Target: finalRuleTargetCIDR,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeRuleForFinalOutput(tt.rule)
			if err != nil {
				t.Fatalf("normalizeRuleForFinalOutput returned error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("unexpected normalized rule:\n got: %#v\nwant: %#v", got, tt.want)
			}
		})
	}
}

func TestSplitRulesForFinalOutputSeparatesDomainsCIDRAndGroups(t *testing.T) {
	t.Parallel()

	dataByGroup, err := splitRulesForFinalOutput([]sourcedRule{
		{Rule: "DOMAIN,pl-res.online.sberbank.ru", Source: "providers/v2fly/Ozon.mihomo", Group: "common"},
		{Rule: "DOMAIN-SUFFIX,ru", Source: "custom/default.yaml", Group: "common"},
		{Rule: "DOMAIN,login.live.com", Source: "providers/blackmatrix7/Xbox.mihomo", Group: "common"},
		{Rule: "IP-CIDR,10.0.0.0/8", Source: "providers/hxehex/Whitelist_cidr.mihomo", Group: "common"},
		{Rule: "IP-CIDR6,2001:db8::/32", Source: "providers/hxehex/Whitelist_cidr.mihomo", Group: "common"},
		{Rule: "DOMAIN-KEYWORD,sber", Source: "custom/default.yaml", Group: "common"},
		{Rule: "DOMAIN,store.steampowered.com", Source: "custom/steam.yaml", Group: "games"},
		{Rule: "IP-ASN,32590", Source: "custom/steam.yaml", Group: "games"},
		{Rule: "IP-CIDR,45.121.184.0/24,no-resolve", Source: "custom/steam.yaml", Group: "games"},
		{Rule: "IP-CIDR6,2404:3fc0::/48,no-resolve", Source: "custom/steam.yaml", Group: "games"},
	})
	if err != nil {
		t.Fatalf("splitRulesForFinalOutput returned error: %v", err)
	}

	commonData, ok := dataByGroup["common"]
	if !ok {
		t.Fatalf("splitRulesForFinalOutput did not return common group: %#v", dataByGroup)
	}
	gamesData, ok := dataByGroup["games"]
	if !ok {
		t.Fatalf("splitRulesForFinalOutput did not return games group: %#v", dataByGroup)
	}

	wantCommonDomainRules := []string{
		"DOMAIN-SUFFIX,ru",
		"DOMAIN-SUFFIX,login.live.com",
		"DOMAIN-KEYWORD,sber",
	}
	wantCommonCIDRRules := []string{
		"IP-CIDR,10.0.0.0/8,no-resolve",
		"IP-CIDR6,2001:db8::/32,no-resolve",
	}
	wantCommonResolvableHosts := []string{
		"pl-res.online.sberbank.ru",
		"login.live.com",
	}
	wantGamesDomainRules := []string{
		"DOMAIN-SUFFIX,store.steampowered.com",
	}
	wantGamesCIDRRules := []string{
		"IP-ASN,32590,no-resolve",
		"IP-CIDR,45.121.184.0/24,no-resolve",
		"IP-CIDR6,2404:3fc0::/48,no-resolve",
	}
	wantGamesResolvableHosts := []string{
		"store.steampowered.com",
	}

	if !reflect.DeepEqual(groupedValues(commonData.DomainRules), wantCommonDomainRules) {
		t.Fatalf("unexpected normalized common domain rules:\n got: %#v\nwant: %#v", groupedValues(commonData.DomainRules), wantCommonDomainRules)
	}
	if !reflect.DeepEqual(groupedValues(commonData.CIDRRules), wantCommonCIDRRules) {
		t.Fatalf("unexpected normalized common CIDR rules:\n got: %#v\nwant: %#v", groupedValues(commonData.CIDRRules), wantCommonCIDRRules)
	}
	if !reflect.DeepEqual(groupedValues(commonData.ResolvableHosts), wantCommonResolvableHosts) {
		t.Fatalf("unexpected common resolvable hosts:\n got: %#v\nwant: %#v", groupedValues(commonData.ResolvableHosts), wantCommonResolvableHosts)
	}
	if !reflect.DeepEqual(commonData.DomainRules[0].Sources, []string{"custom/default.yaml"}) {
		t.Fatalf("unexpected sources for common DOMAIN-SUFFIX,ru: %#v", commonData.DomainRules[0].Sources)
	}

	if !reflect.DeepEqual(groupedValues(gamesData.DomainRules), wantGamesDomainRules) {
		t.Fatalf("unexpected normalized games domain rules:\n got: %#v\nwant: %#v", groupedValues(gamesData.DomainRules), wantGamesDomainRules)
	}
	if !reflect.DeepEqual(groupedValues(gamesData.CIDRRules), wantGamesCIDRRules) {
		t.Fatalf("unexpected normalized games CIDR rules:\n got: %#v\nwant: %#v", groupedValues(gamesData.CIDRRules), wantGamesCIDRRules)
	}
	if !reflect.DeepEqual(groupedValues(gamesData.ResolvableHosts), wantGamesResolvableHosts) {
		t.Fatalf("unexpected games resolvable hosts:\n got: %#v\nwant: %#v", groupedValues(gamesData.ResolvableHosts), wantGamesResolvableHosts)
	}
}

func TestEffectiveTLDPlusTwo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "adds one label above etld plus one",
			value: "test1.test2.test3.ru",
			want:  "test2.test3.ru",
		},
		{
			name:  "returns registrable domain when extra label is absent",
			value: "test3.ru",
			want:  "test3.ru",
		},
		{
			name:  "keeps full host when only one label is above registrable domain",
			value: "login.live.com",
			want:  "login.live.com",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := effectiveTLDPlusTwo(tt.value)
			if err != nil {
				t.Fatalf("effectiveTLDPlusTwo returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected effectiveTLDPlusTwo value: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestResolveOutputPathUsesConfiguredOutput(t *testing.T) {
	t.Parallel()

	outputPath := resolveOutputPath(BuildConfig{
		Output: "dist/ru.yaml",
	}, Options{})

	if outputPath != filepath.Clean("dist/ru.yaml") {
		t.Fatalf("unexpected output path: %q", outputPath)
	}
}

func TestGroupOutputPathUsesNormalizedGroupSubdirectory(t *testing.T) {
	t.Parallel()

	got := groupOutputPath("dist/ru.yaml", "Games")
	want := filepath.Clean(filepath.Join("dist", "games", "ru.yaml"))
	if got != want {
		t.Fatalf("unexpected grouped output path: got %q want %q", got, want)
	}
}

func TestMergeFinalRulesKeepsDomainsBeforeCIDR(t *testing.T) {
	t.Parallel()

	got := mergeFinalRules(
		[]groupedValue{{Value: "IP-CIDR,10.0.0.0/8,no-resolve"}},
		[]groupedValue{{Value: "DOMAIN-SUFFIX,example.com"}},
	)

	want := []string{
		"DOMAIN-SUFFIX,example.com",
		"IP-CIDR,10.0.0.0/8,no-resolve",
	}

	if !reflect.DeepEqual(groupedValues(got), want) {
		t.Fatalf("unexpected merged rule order:\n got: %#v\nwant: %#v", groupedValues(got), want)
	}
}

func TestDeriveCIDRRulesFromDomains(t *testing.T) {
	t.Parallel()

	b := builder{
		lookupIPFunc: func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "pl-res.online.sberbank.ru":
				return []netip.Addr{netip.MustParseAddr("194.54.14.1")}, nil
			case "login.live.com":
				return []netip.Addr{netip.MustParseAddr("13.107.42.16")}, nil
			default:
				return nil, nil
			}
		},
	}

	got, err := b.deriveCIDRRulesFromDomains([]groupedValue{
		{Value: "pl-res.online.sberbank.ru", Sources: []string{"providers/v2fly/Ozon.mihomo"}},
		{Value: "login.live.com", Sources: []string{"providers/blackmatrix7/Xbox.mihomo"}},
		{Value: "pl-res.online.sberbank.ru", Sources: []string{"providers/v2fly/Ozon.mihomo"}},
	})
	if err != nil {
		t.Fatalf("deriveCIDRRulesFromDomains returned error: %v", err)
	}

	want := []string{
		"IP-CIDR,194.54.14.0/24,no-resolve",
		"IP-CIDR,13.107.42.0/24,no-resolve",
	}

	if !reflect.DeepEqual(groupedValues(got), want) {
		t.Fatalf("unexpected derived CIDR rules:\n got: %#v\nwant: %#v", groupedValues(got), want)
	}
	if !reflect.DeepEqual(got[0].Sources, []string{"providers/v2fly/Ozon.mihomo [derived from pl-res.online.sberbank.ru]"}) {
		t.Fatalf("unexpected derived sources: %#v", got[0].Sources)
	}
}

func TestAddNoResolveOption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ruleType string
		value    string
		want     string
	}{
		{
			name:     "adds option when missing",
			ruleType: "IP-CIDR",
			value:    "10.0.0.0/8",
			want:     "IP-CIDR,10.0.0.0/8,no-resolve",
		},
		{
			name:     "preserves existing no-resolve",
			ruleType: "IP-CIDR6",
			value:    "2001:db8::/32,no-resolve",
			want:     "IP-CIDR6,2001:db8::/32,no-resolve",
		},
		{
			name:     "supports ip asn",
			ruleType: "IP-ASN",
			value:    "32590",
			want:     "IP-ASN,32590,no-resolve",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := addNoResolveOption(tt.ruleType, tt.value); got != tt.want {
				t.Fatalf("unexpected normalized rule: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestCollectConfiguredProviderRuleFilesUsesDeclaredEntriesOnly(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Providers: []ProviderConfig{
			{
				Name:      "sample",
				TargetDir: filepath.Join("providers", "sample"),
				Files: []RemoteFile{
					{Name: "wanted.mihomo", Group: "Games", URL: "https://example.com/wanted.mihomo"},
					{Name: "source.raw", URL: "https://example.com/source.raw"},
				},
			},
		},
	}

	got, err := collectConfiguredProviderRuleFiles(cfg)
	if err != nil {
		t.Fatalf("collectConfiguredProviderRuleFiles returned error: %v", err)
	}

	want := []ruleFile{
		{
			Path:  filepath.Clean(filepath.Join("providers", "sample", "wanted.mihomo")),
			Group: "games",
		},
		{
			Path:  filepath.Clean(filepath.Join("providers", "sample", "source.mihomo")),
			Group: "common",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected provider rule files:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestLoadConfigSupportsGroupedProviderFormat(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "conf.yaml")
	content := strings.TrimSpace(`
build:
  output: dist/ru.yaml

providers:
  - name: sample
    target_dir: providers/sample
    files:
      common.raw: https://example.com/common.raw
    groups:
      games:
        steam.mihomo: https://example.com/steam.mihomo
`) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	want := []ProviderConfig{
		{
			Name:      "sample",
			TargetDir: filepath.Clean(filepath.Join("providers", "sample")),
			Files: []RemoteFile{
				{Name: "common.raw", Group: "common", URL: "https://example.com/common.raw"},
				{Name: "steam.mihomo", Group: "games", URL: "https://example.com/steam.mihomo"},
			},
		},
	}

	if !reflect.DeepEqual(cfg.Providers, want) {
		t.Fatalf("unexpected providers after load:\n got: %#v\nwant: %#v", cfg.Providers, want)
	}
}

func TestLoadConfigRejectsLegacyProviderFileListFormat(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "conf.yaml")
	content := strings.TrimSpace(`
providers:
  - name: sample
    target_dir: providers/sample
    files:
      - name: old.raw
        url: https://example.com/old.raw
`) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig unexpectedly accepted legacy provider file list format")
	}
}

func TestLoadConfigRejectsLegacyCustomFilesFormat(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "conf.yaml")
	content := strings.TrimSpace(`
custom:
  target_dir: custom
  files:
    - name: default.yaml
`) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig unexpectedly accepted legacy custom files format")
	}
}

func TestCollectConfiguredCustomRuleFilesUsesDeclaredEntriesOnly(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Custom: CustomConfig{
			TargetDir: filepath.Join("custom"),
			Groups: map[string][]string{
				"Games":  {"steam.yaml"},
				"Common": {"default.yaml"},
			},
		},
	}

	cfg.Custom = normalizeCustomConfig(cfg.Custom)

	got := collectConfiguredCustomRuleFiles(cfg)

	want := []ruleFile{
		{
			Path:  filepath.Clean(filepath.Join("custom", "default.yaml")),
			Group: "common",
		},
		{
			Path:  filepath.Clean(filepath.Join("custom", "steam.yaml")),
			Group: "games",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected custom rule files:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestCollectRuleFilesDoesNotAutoDiscoverCustomWhenCustomNotConfigured(t *testing.T) {
	dir := t.TempDir()
	customDir := filepath.Join(dir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatalf("create custom dir: %v", err)
	}
	customPath := filepath.Join(customDir, "default.yaml")
	if err := os.WriteFile(customPath, []byte("payload:\n  - DOMAIN-SUFFIX,example.com\n"), 0o644); err != nil {
		t.Fatalf("write custom file: %v", err)
	}

	t.Chdir(dir)

	got, err := collectRuleFiles(Config{})
	if err != nil {
		t.Fatalf("collectRuleFiles returned error: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("collectRuleFiles unexpectedly auto-discovered custom files: %#v", got)
	}
}

func TestValidateConfigRejectsUnsafeFileNames(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Providers: []ProviderConfig{
			{
				Name:      "sample",
				TargetDir: "providers/sample",
				Files: []RemoteFile{
					{Name: "../escape.mihomo", URL: "https://example.com/escape.mihomo"},
				},
			},
		},
	}

	if err := validateConfig(cfg); err == nil {
		t.Fatal("validateConfig unexpectedly accepted unsafe file name")
	}
}

func TestValidateConfigRejectsCustomTargetDirWithoutGroups(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Custom: CustomConfig{
			TargetDir: "custom",
		},
	}

	if err := validateConfig(cfg); err == nil {
		t.Fatal("validateConfig unexpectedly accepted custom target_dir without groups")
	}
}

func TestValidateConfigRejectsUnsafeCustomFileNames(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Custom: CustomConfig{
			TargetDir: "custom",
			Groups: map[string][]string{
				"common": {"../escape.yaml"},
			},
		},
	}

	if err := validateConfig(cfg); err == nil {
		t.Fatal("validateConfig unexpectedly accepted unsafe custom file name")
	}
}

func TestValidateConfigRejectsUnsafeGroupNames(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Providers: []ProviderConfig{
			{
				Name:      "sample",
				TargetDir: "providers/sample",
				Files: []RemoteFile{
					{Name: "safe.mihomo", Group: "../games", URL: "https://example.com/safe.mihomo"},
				},
			},
		},
	}

	if err := validateConfig(cfg); err == nil {
		t.Fatal("validateConfig unexpectedly accepted unsafe group name")
	}
}

func TestValidateConfigRejectsUnsafeCustomGroupNames(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Custom: CustomConfig{
			TargetDir: "custom",
			Groups: map[string][]string{
				"../games": {"safe.yaml"},
			},
		},
	}

	cfg.Custom = normalizeCustomConfig(cfg.Custom)

	if err := validateConfig(cfg); err == nil {
		t.Fatal("validateConfig unexpectedly accepted unsafe custom group name")
	}
}

func groupedValues(values []groupedValue) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Value)
	}
	return out
}
