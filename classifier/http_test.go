package classifier

import (
	"slices"
	"testing"
)

func TestHTTPClassifiesEncodedTraversalAndDropsQuery(t *testing.T) {
	classifier, err := NewHTTPClassifier(DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := classifier.Classify(HTTPRequest{
		EventID:       "nginx:1",
		RequestTarget: "/assets/%252e%252e%252fetc/passwd?token=must-not-leak",
		Status:        404,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Eligible {
		t.Fatal("encoded traversal was not classified")
	}
	if decision.Path != "/assets/%252e%252e%252fetc/passwd" {
		t.Fatalf("published path = %q", decision.Path)
	}
	if decision.MatchedRepresentation != "decoded_twice" {
		t.Fatalf("matched representation = %q, want decoded_twice", decision.MatchedRepresentation)
	}
	wantRules := []string{RuleHTTPTraversal, RuleHTTPSensitiveFile}
	if !slices.Equal(decision.RuleIDs, wantRules) {
		t.Fatalf("rules = %v, want %v", decision.RuleIDs, wantRules)
	}
}

func TestHTTPRequiresEligibleStatusAndHonorsRouteExclusion(t *testing.T) {
	config := DefaultHTTPConfig()
	config.ExcludedPathPrefixes = []string{"/download/"}
	classifier, err := NewHTTPClassifier(config)
	if err != nil {
		t.Fatal(err)
	}

	for _, request := range []HTTPRequest{
		{EventID: "nginx:2", RequestTarget: "/../etc/passwd", Status: 200},
		{EventID: "nginx:3", RequestTarget: "/download/../report", Status: 404},
		{EventID: "nginx:4", RequestTarget: "/missing", Status: 404},
	} {
		decision, err := classifier.Classify(request)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Eligible {
			t.Fatalf("request %#v was unexpectedly eligible", request)
		}
	}
}

func TestHTTPRejectsSensitivePathContents(t *testing.T) {
	classifier, err := NewHTTPClassifier(DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := classifier.Classify(HTTPRequest{
		EventID:       "nginx:5",
		RequestTarget: "/users/alice@example.com/../../etc/passwd",
		Status:        404,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Eligible {
		t.Fatal("path containing an email address was eligible")
	}
}

func TestHTTPRejectsAbsoluteFormRequestTarget(t *testing.T) {
	classifier, err := NewHTTPClassifier(DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := classifier.Classify(HTTPRequest{
		EventID:       "proxy:1",
		RequestTarget: "http:example.test/../etc/passwd",
		Status:        404,
	})
	if err != nil {
		t.Fatalf("unexpected error for absolute-form request target: %v", err)
	}
	if decision.Eligible {
		t.Fatal("absolute-form request target was unexpectedly eligible")
	}
}

func TestHTTPClassifiesMalformedRequestsAsIneligible(t *testing.T) {
	classifier, err := NewHTTPClassifier(DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Test case 1: Request target not starting with "/"
	decision, err := classifier.Classify(HTTPRequest{
		EventID:       "nginx:1",
		RequestTarget: "CONNECT example.com:443",
		Status:        404,
	})
	if err != nil {
		t.Fatalf("unexpected error for malformed request target: %v", err)
	}
	if decision.Eligible {
		t.Fatal("request with non-origin-form target was unexpectedly eligible")
	}

	// Test case 2: Empty request target after stripping (which also fails origin-form check)
	decision, err = classifier.Classify(HTTPRequest{
		EventID:       "nginx:2",
		RequestTarget: "",
		Status:        404,
	})
	if err != nil {
		t.Fatalf("unexpected error for empty request target: %v", err)
	}
	if decision.Eligible {
		t.Fatal("request with empty target was unexpectedly eligible")
	}
}

func TestHTTPClassifiesKnownCVEProbes(t *testing.T) {
	classifier, err := NewHTTPClassifier(DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		target string
		path   string
		rules  []string
	}{
		{"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", []string{"http/cve-2017-9841-v1"}},
		{"/GponForm/diag_Form?images/", "/GponForm/diag_Form", []string{"http/cve-2018-10561-v1"}},
		{"/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", "/remote/fgt_lang", []string{"http/cve-2018-13379-v1"}},
		{`/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`, "/index.php", []string{"http/cve-2018-20062-v1"}},
		{"/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua", "/+CSCOT+/oem-customization", []string{"http/cve-2020-3452-v1"}},
		{"/SDK/webLanguage", "/SDK/webLanguage", []string{"http/cve-2021-36260-v1"}},
		{"/api/v2/cmdb/system/admin/admin", "/api/v2/cmdb/system/admin/admin", []string{"http/cve-2022-40684-v1"}},
		{"/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)", "/cgi-bin/luci/;stok=/locale", []string{"http/cve-2023-1389-v1"}},
		{"/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=cd+/tmp", "/device.rsp", []string{"http/cve-2024-3721-v1"}},
		{"/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "/index.php", []string{"http/cve-2024-4577-v1"}},
		{"/@fs/../../../../../proc/self/environ?raw??", "/@fs/../../../../../proc/self/environ", []string{"http/cve-2025-30208-v1", RuleHTTPTraversal, RuleHTTPSensitiveFile}},
		{"/developmentserver/metadatauploader", "/developmentserver/metadatauploader", []string{"http/cve-2025-31324-v1"}},
	} {
		decision, err := classifier.Classify(HTTPRequest{EventID: "nginx:cve", RequestTarget: test.target, Status: 404})
		if err != nil {
			t.Fatal(err)
		}
		if !decision.Eligible {
			t.Errorf("%s was not classified", test.target)
			continue
		}
		if decision.Path != test.path {
			t.Errorf("%s: published path = %q, want %q", test.target, decision.Path, test.path)
		}
		if !slices.Equal(decision.RuleIDs, test.rules) {
			t.Errorf("%s: rules = %v, want %v", test.target, decision.RuleIDs, test.rules)
		}
	}
}

func TestHTTPDoesNotClassifyProductFingerprints(t *testing.T) {
	classifier, err := NewHTTPClassifier(DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/geoserver/web/",
		"/HNAP1/",
		"/dana-na/nc/nc_gina_ver.txt",
		"/WebInterface/login.html",
		"/device.rsp?opt=user&cmd=list",
		"/search?q=phpunit",
	} {
		decision, err := classifier.Classify(HTTPRequest{EventID: "nginx:fp", RequestTarget: target, Status: 404})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Eligible {
			t.Errorf("%s was classified as %v", target, decision.RuleIDs)
		}
	}
}

func TestHTTPCVEProbeHonorsRouteExclusion(t *testing.T) {
	config := DefaultHTTPConfig()
	config.ExcludedPathPrefixes = []string{"/index.php"}
	classifier, err := NewHTTPClassifier(config)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := classifier.Classify(HTTPRequest{
		EventID:       "nginx:excluded",
		RequestTarget: "/index.php?s=index/think\\app/invokefunction",
		Status:        404,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Eligible {
		t.Fatal("excluded route was eligible through a CVE signature")
	}
}

func TestHTTPClassifiesSecretFileProbes(t *testing.T) {
	classifier, err := NewHTTPClassifier(DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/.aws/credentials",
		"/.git/HEAD",
		"/docker-compose.override.yml",
		"/appsettings.Production.json",
		"/config/secrets.yml",
		"/wp-config.php.bak",
		"/.config/gcloud/application_default_credentials.json",
		"/.ssh/id_rsa",
		"/terraform.tfstate.backup",
		"/backup.sql",
	} {
		decision, err := classifier.Classify(HTTPRequest{EventID: "nginx:secret", RequestTarget: target, Status: 404})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(decision.RuleIDs, []string{RuleHTTPSensitiveFile}) {
			t.Errorf("%s: rules = %v, want [%s]", target, decision.RuleIDs, RuleHTTPSensitiveFile)
		}
	}
	for _, target := range []string{"/config.json", "/config.js", "/.github/workflows/ci.yml", "/assets/config.json"} {
		decision, err := classifier.Classify(HTTPRequest{EventID: "nginx:generic", RequestTarget: target, Status: 404})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Eligible {
			t.Errorf("%s was classified as %v", target, decision.RuleIDs)
		}
	}
}
