package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	configPath := flag.String("config", "conf.yaml", "path to config file")
	outputPath := flag.String("output", "", "override output ruleset path")
	skipDownload := flag.Bool("skip-download", false, "skip downloading provider files and use local files only")
	deriveCIDR := flag.Bool("derive-cidr", false, "resolve domain-derived hosts to live /32 or /128 CIDR entries")
	flag.Parse()

	opts := Options{
		ConfigPath:   *configPath,
		OutputPath:   *outputPath,
		SkipDownload: *skipDownload,
		DeriveCIDR:   *deriveCIDR,
		Stdout:       os.Stdout,
	}

	if err := Run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "mihomo_rules: %v\n", err)
		os.Exit(1)
	}
}
