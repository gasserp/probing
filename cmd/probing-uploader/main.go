package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gasserp/probing/uploader"
)

func main() {
	githubRepository := flag.String("github-repository", "", "public owner/name GitHub repository to commit batches to, instead of Azure")
	account := flag.String("account", "", "Azure Storage account name")
	container := flag.String("container", "", "Azure Blob container name")
	outbox := flag.String("outbox", "/outbox", "shared outbox directory")
	poll := flag.Duration("poll", 15*time.Second, "outbox polling interval")
	tenantID := flag.String("tenant-id", "", "Entra tenant ID; omit to use the Azure VM managed identity")
	clientID := flag.String("client-id", "", "Entra service principal client ID")
	credentialFile := flag.String("credential-file", "", "file holding the GitHub token or the service principal client secret")
	flag.Parse()
	if *githubRepository == "" && (*account == "" || *container == "") {
		fmt.Fprintln(os.Stderr, "usage: probing-uploader -github-repository <owner/name> -credential-file <path> [-outbox <path>]\n"+
			"   or: probing-uploader -account <name> -container <name> [-outbox <path>]"+
			" [-tenant-id <id> -client-id <id> -credential-file <path>]")
		os.Exit(2)
	}
	process, err := uploader.New(uploader.Config{
		GitHubRepository: *githubRepository,
		Account:          *account,
		Container:        *container,
		OutboxDir:        *outbox,
		PollInterval:     *poll,
		TenantID:         *tenantID,
		ClientID:         *clientID,
		CredentialFile:   *credentialFile,
	})
	if err != nil {
		log.Printf("probing-uploader configuration failed: %v", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := process.Run(ctx); err != nil {
		log.Printf("probing-uploader stopped: %v", err)
		os.Exit(1)
	}
}
