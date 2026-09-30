package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gasserp/probing/ingest"
)

func main() {
	repositoryPath := flag.String("repo", "", "checked-out probing-data repository")
	repositoryIdentity := flag.String("repository", "", "expected owner/name data repository identity")
	outputPath := flag.String("output", "", "directory to write the deny list files into")
	flag.Parse()
	if *repositoryPath == "" || *repositoryIdentity == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: probing-deny-list -repo <path> -repository <owner/name> -output <dir>")
		os.Exit(2)
	}
	if err := ingest.WriteDenyLists(*repositoryPath, *repositoryIdentity, *outputPath, time.Now().UTC()); err != nil {
		log.Printf("probing-deny-list failed: %v", err)
		os.Exit(1)
	}
}
