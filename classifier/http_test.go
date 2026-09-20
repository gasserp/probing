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
