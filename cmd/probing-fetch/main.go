package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gasserp/probing/fetch"
	"github.com/gasserp/probing/ingest"
)

func main() {
	repositoryPath := flag.String("repo", "", "checked-out probing-data repository")
	outputPath := flag.String("output", "", "directory to add fetched batches to, usually probing-ingest's -input")
	repositoryIdentity := flag.String("repository", "", "expected owner/name data repository identity")
	flag.Parse()
	if *repositoryPath == "" || *outputPath == "" || *repositoryIdentity == "" {
		fmt.Fprintln(os.Stderr, "usage: probing-fetch -repo <path> -output <path> -repository <owner/name>")
		os.Exit(2)
	}
	targets, err := ingest.FetchTargets(*repositoryPath, *repositoryIdentity)
	if err != nil {
		log.Printf("probing-fetch failed: %v", err)
		os.Exit(1)
	}
	report, err := fetch.Run(context.Background(), fetch.Options{
		Targets:    targets,
		OutputPath: *outputPath,
		Token:      os.Getenv("GITHUB_TOKEN"),
	})
	// One unreachable or malformed contributor repository must not hold back
	// everyone else's batches, so per-source failures are warnings.
	warning := ""
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		warning = "::warning::"
	}
	for _, failure := range report.Failures {
		fmt.Printf("%sprobing-fetch: source %s (%s): %v\n", warning, failure.SourceID, failure.Repository, failure.Err)
	}
	if err != nil {
		log.Printf("probing-fetch failed: %v", err)
		os.Exit(1)
	}
	log.Printf("probing-fetch sources=%d fetched=%d failed=%d", len(targets), report.Fetched, len(report.Failures))
}
