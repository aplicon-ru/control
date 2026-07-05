package deploy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Healthcheck GETs u with ctx's deadline and treats any 2xx response as
// pass. It runs from CP itself — see resolveHealthcheckURL for rewriting
// a module-authored "localhost" URL to the target server's address first.
func Healthcheck(ctx context.Context, client *http.Client, u string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("deploy: healthcheck: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("deploy: healthcheck: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("deploy: healthcheck: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// resolveHealthcheckURL rewrites a "localhost"/"127.0.0.1"/"::1" host in
// rawURL to targetHost. module_versions.healthcheck_url is authored from
// the container's own point of view (e.g. "http://localhost:8001/health"
// in the spec's own module.yaml example) — CP is not that host, so a
// literal GET from CP would hit the wrong machine.
func resolveHealthcheckURL(rawURL, targetHost string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("deploy: resolve healthcheck url: %w", err)
	}

	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		if port := u.Port(); port != "" {
			u.Host = targetHost + ":" + port
		} else {
			u.Host = targetHost
		}
	}
	return u.String(), nil
}
