// ---
// relationships:
//   implements: controller
//   uses: configuration
// ---

package updates

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
)

const latestReleaseURL = "https://github.com/wyrd-company/wyrwood/releases/latest"

var (
	errReleaseResponse = errors.New("release redirect unavailable")
	errReleaseLocation = errors.New("unexpected release location")
	errReleaseVersion  = errors.New("release tag is not SemVer")
)

// Status is an in-memory observation. Latest and LastSuccess survive a failed
// check; Checked identifies the most recent completed attempt.
type Status struct {
	Enabled     bool
	Latest      string
	Checked     time.Time
	LastSuccess time.Time
	Unavailable bool
}

// Checker owns the release-check loop and its last observation.
type Checker struct {
	configuration config.UpdateChecks
	client        *http.Client
	log           io.Writer
	mu            sync.Mutex
	status        Status
}

// New creates a checker without making a request. A transport can be supplied
// for tests; this client never shares OIDC cookies, credentials, or redirects.
func New(configuration config.UpdateChecks, transport http.RoundTripper, log io.Writer) *Checker {
	if log == nil {
		log = io.Discard
	}
	if configuration.Interval <= 0 {
		configuration.Interval = config.DefaultUpdateInterval
	}
	if configuration.Timeout <= 0 {
		configuration.Timeout = config.DefaultUpdateTimeout
	}
	return &Checker{configuration: configuration, log: log, status: Status{Enabled: configuration.Enabled}, client: &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Status returns a snapshot without network I/O.
func (checker *Checker) Status() Status {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	return checker.status
}

// Run checks once at startup, then waits the configured interval after each
// attempt. Checks never overlap and failures have no separate retry schedule.
func (checker *Checker) Run(ctx context.Context) {
	if !checker.configuration.Enabled {
		return
	}
	for ctx.Err() == nil {
		checker.check(ctx)
		timer := time.NewTimer(checker.configuration.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (checker *Checker) check(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, checker.configuration.Timeout)
	defer cancel()
	latest, err := checker.latest(ctx)
	checker.mu.Lock()
	checker.status.Checked = time.Now().UTC()
	checker.status.Unavailable = err != nil
	if err == nil {
		checker.status.Latest = latest
		checker.status.LastSuccess = checker.status.Checked
	}
	checker.mu.Unlock()
	if err != nil && !errors.Is(err, context.Canceled) {
		// Only fixed categories reach the journal; errors can contain private
		// proxy addresses or other operator details.
		_, _ = fmt.Fprintf(checker.log, "wyrwood controller: release check failed (%s)\n", failureCategory(err))
	}
}

func (checker *Checker) latest(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, latestReleaseURL, nil)
	if err != nil {
		return "", err
	}
	response, err := checker.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return "", errReleaseResponse
	}
	location, err := response.Location()
	if err != nil {
		return "", errReleaseLocation
	}
	const tagPath = "/wyrd-company/wyrwood/releases/tag/"
	if location.Scheme != "https" || location.Host != "github.com" || location.User != nil || !strings.HasPrefix(location.Path, tagPath) {
		return "", errReleaseLocation
	}
	tag := strings.TrimPrefix(location.Path, tagPath)
	if !Valid(tag) {
		return "", errReleaseVersion
	}
	return tag, nil
}

func failureCategory(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errReleaseResponse):
		return "response"
	case errors.Is(err, errReleaseLocation):
		return "location"
	case errors.Is(err, errReleaseVersion):
		return "version"
	default:
		return "network"
	}
}
