// Command probing-insights writes the dashboard's insights.json from a
// checked-out probing-data repository. Geolocation is optional: without the
// DB-IP Lite files the output still carries exact totals, but no countries or
// networks.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gasserp/probing/geoip"
	"github.com/gasserp/probing/ingest"
)

func main() {
	repositoryPath := flag.String("repo", "", "checked-out probing-data repository")
	repositoryIdentity := flag.String("repository", "", "expected owner/name data repository identity")
	outputFile := flag.String("output", "", "file to write insights.json to")
	countryPath := flag.String("country-db", "", "optional DB-IP IP to Country Lite CSV (.csv or .csv.gz)")
	networkPath := flag.String("asn-db", "", "optional DB-IP IP to ASN Lite CSV (.csv or .csv.gz)")
	flag.Parse()
	if *repositoryPath == "" || *repositoryIdentity == "" || *outputFile == "" {
		fmt.Fprintln(os.Stderr, "usage: probing-insights -repo <path> -repository <owner/name> -output <file> [-country-db <csv>] [-asn-db <csv>]")
		os.Exit(2)
	}
	geo := ingest.Geolocation{Attribution: &ingest.GeoAttribution{
		Provider: "DB-IP",
		URL:      "https://db-ip.com",
		License:  "CC BY 4.0",
	}}
	// A missing or unreadable database degrades the dashboard rather than
	// failing the publication of everything else.
	if *countryPath != "" {
		countries, err := geoip.LoadCountries(*countryPath)
		if err != nil {
			log.Printf("probing-insights: continuing without countries: %v", err)
		} else {
			geo.Countries = countries
			geo.Attribution.CountryDatabase = filepath.Base(*countryPath)
		}
	}
	if *networkPath != "" {
		networks, err := geoip.LoadNetworks(*networkPath)
		if err != nil {
			log.Printf("probing-insights: continuing without networks: %v", err)
		} else {
			geo.Networks = networks
			geo.Attribution.NetworkDatabase = filepath.Base(*networkPath)
		}
	}
	if err := ingest.WriteInsights(*repositoryPath, *repositoryIdentity, *outputFile, geo, time.Now().UTC()); err != nil {
		log.Printf("probing-insights failed: %v", err)
		os.Exit(1)
	}
}
