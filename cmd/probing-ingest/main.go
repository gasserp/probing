package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gasserp/probing/ingest"
)

func main() {
	repositoryPath := flag.String("repo", "", "checked-out probing-data repository")
	inputPath := flag.String("input", "", "directory containing downloaded Azure blobs")
	repositoryIdentity := flag.String("repository", "", "expected owner/name data repository identity")
	acceptedManifest := flag.String("accepted-manifest", "", "optional path for a bounded JSON list of blobs safe to delete after commit")
	flag.Parse()
	if *repositoryPath == "" || *inputPath == "" || *repositoryIdentity == "" {
		fmt.Fprintln(os.Stderr, "usage: probing-ingest -repo <path> -input <path> -repository <owner/name>")
		os.Exit(2)
	}
	result, err := ingest.Run(context.Background(), ingest.Options{
		RepositoryPath:     *repositoryPath,
		InputPath:          *inputPath,
		RepositoryIdentity: *repositoryIdentity,
		AcceptedManifest:   *acceptedManifest,
	})
	if err != nil {
		log.Printf("probing-ingest failed: %v", err)
		os.Exit(1)
	}
	log.Printf(
		"probing-ingest accepted=%d replayed=%d quarantined=%d",
		result.Accepted,
		result.Replayed,
		result.Quarantined,
	)
	if result.Quarantined > 0 {
		os.Exit(3)
	}
}
