// ---
// relationships:
//   verifies:
//     - controller
//     - configuration
// ---

package controller

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
)

type failingReleaseTransport struct{}

func (failingReleaseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("sample-private-detail")
}

type releaseJournal chan string

func (journal releaseJournal) Write(data []byte) (int, error) {
	journal <- string(data)
	return len(data), nil
}

func TestReleaseCheckerUsesControllerJournal(t *testing.T) {
	journal := make(releaseJournal, 1)
	instance, err := New(config.Controller{
		StateDirectory: t.TempDir(),
		OpenBao:        config.ControllerOpenBao{Address: "http://127.0.0.1:8200"},
		UpdateChecks:   config.UpdateChecks{Enabled: true, Interval: time.Hour},
	}, Options{ReleaseTransport: failingReleaseTransport{}, Log: journal})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() { defer close(done); instance.updates.Run(ctx) }()
	select {
	case line := <-journal:
		if line != "wyrwood controller: release check failed (network)\n" {
			t.Fatalf("journal = %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("release checker did not use controller journal")
	}
}
