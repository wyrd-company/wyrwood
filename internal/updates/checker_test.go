// ---
// relationships:
//   verifies:
//     - controller
//     - configuration
// ---

package updates

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func redirect(r *http.Request, location string) *http.Response {
	return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {location}}, Body: io.NopCloser(strings.NewReader("")), Request: r}
}

func TestRunIsOptInAndChecksAtStartupAndConfiguredInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			if r.Method != http.MethodHead || r.URL.String() != latestReleaseURL {
				t.Errorf("release request = %s %s", r.Method, r.URL)
			}
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("release request carries credentials")
			}
			return redirect(r, "https://github.com/wyrd-company/wyrwood/releases/tag/3.4.5"), nil
		})
		disabled := New(config.UpdateChecks{}, transport)
		disabled.Run(context.Background())
		if calls.Load() != 0 || disabled.Status().Enabled {
			t.Fatal("disabled checker made a request")
		}
		checker := New(config.UpdateChecks{Enabled: true, Interval: 37 * time.Minute}, transport)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go checker.Run(ctx)
		synctest.Wait()
		if calls.Load() != 1 || checker.Status().Latest != "3.4.5" {
			t.Fatalf("startup = %d calls, %#v", calls.Load(), checker.Status())
		}
		time.Sleep(37*time.Minute - time.Nanosecond)
		if calls.Load() != 1 {
			t.Fatal("checked before configured interval")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatalf("interval = %d requests", calls.Load())
		}
		cancel()
		synctest.Wait()
		time.Sleep(time.Hour)
		if calls.Load() != 2 {
			t.Fatal("requests continued after shutdown")
		}
	})
}

func TestConfiguredTimeoutCancelsRequestWithoutImmediateRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		checker := New(config.UpdateChecks{Enabled: true, Interval: time.Minute, Timeout: 7 * time.Second}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go checker.Run(ctx)
		synctest.Wait()
		time.Sleep(7*time.Second - time.Nanosecond)
		if !checker.Status().Checked.IsZero() {
			t.Fatal("request stopped before configured timeout")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if !checker.Status().Unavailable || checker.Status().Checked.IsZero() {
			t.Fatalf("timeout = %#v", checker.Status())
		}
		time.Sleep(time.Minute - time.Nanosecond)
		if calls.Load() != 1 {
			t.Fatal("failed request retried before interval")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("failure was not checked again at interval")
		}
		cancel()
		synctest.Wait()
	})
}

func TestShutdownCancelsInFlightCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var finished atomic.Bool
		checker := New(config.UpdateChecks{Enabled: true, Timeout: time.Hour}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			finished.Store(true)
			return nil, r.Context().Err()
		}))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go checker.Run(ctx)
		synctest.Wait()
		cancel()
		synctest.Wait()
		if !finished.Load() {
			t.Fatal("shutdown did not cancel HTTP request")
		}
	})
}

func TestFailureKeepsLastSuccessfulObservationAndRecovers(t *testing.T) {
	failure := false
	checker := New(config.UpdateChecks{Enabled: true}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if failure {
			return nil, errors.New("offline")
		}
		return redirect(r, "https://github.com/wyrd-company/wyrwood/releases/tag/4.5.6"), nil
	}))
	checker.check(context.Background())
	first := checker.Status()
	if first.Unavailable || first.Latest != "4.5.6" || first.LastSuccess.IsZero() {
		t.Fatalf("success = %#v", first)
	}
	failure = true
	checker.check(context.Background())
	failed := checker.Status()
	if !failed.Unavailable || failed.Latest != first.Latest || failed.LastSuccess != first.LastSuccess || failed.Checked.Before(first.Checked) {
		t.Fatalf("failure = %#v", failed)
	}
	failure = false
	checker.check(context.Background())
	if checker.Status().Unavailable || checker.Status().LastSuccess.Before(failed.LastSuccess) {
		t.Fatalf("recovery = %#v", checker.Status())
	}
}

func TestReleaseLookupValidatesRedirectWithoutFollowingIt(t *testing.T) {
	for name, location := range map[string]string{
		"tag":               "https://github.com/wyrd-company/wyrwood/releases/tag/3.4.5-rc.1+sample",
		"relative":          "/wyrd-company/wyrwood/releases/tag/v3.4.5",
		"wrong-host":        "https://example.com/wyrd-company/wyrwood/releases/tag/3.4.5",
		"wrong-repo":        "https://github.com/example/project/releases/tag/3.4.5",
		"http":              "http://github.com/wyrd-company/wyrwood/releases/tag/3.4.5",
		"credentials":       "https://sample@github.com/wyrd-company/wyrwood/releases/tag/3.4.5",
		"not-semver":        "https://github.com/wyrd-company/wyrwood/releases/tag/nightly",
		"incomplete-semver": "https://github.com/wyrd-company/wyrwood/releases/tag/3.4",
		"missing":           "",
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			checker := New(config.UpdateChecks{Enabled: true}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 {
					return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}
				return redirect(r, location), nil
			}))
			checker.check(context.Background())
			status := checker.Status()
			valid := name == "tag" || name == "relative"
			if calls != 1 || status.Unavailable == valid || (valid && !Valid(status.Latest)) {
				t.Fatalf("lookup = %d calls %#v", calls, status)
			}
		})
	}
	for _, statusCode := range []int{http.StatusOK, http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError} {
		checker := New(config.UpdateChecks{Enabled: true}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			response := redirect(r, "https://github.com/wyrd-company/wyrwood/releases/tag/3.4.5")
			response.StatusCode = statusCode
			return response, nil
		}))
		checker.check(context.Background())
		if !checker.Status().Unavailable {
			t.Errorf("accepted HTTP %d", statusCode)
		}
	}
}
