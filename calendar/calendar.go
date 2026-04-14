// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

// Package calendar implements the OpenTimestamps remote calendar HTTP interface.
package calendar

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/opentimestamps/go-opentimestamps/core"
)

// CommitmentNotFoundError is returned when the calendar does not have a commitment.
type CommitmentNotFoundError struct{ Reason string }

func (e *CommitmentNotFoundError) Error() string { return e.Reason }

const (
	maxResponseSize = 10000
	defaultTimeout  = 10 * time.Second
)

// RemoteCalendar is an OpenTimestamps remote calendar server.
type RemoteCalendar struct {
	URL       string
	UserAgent string
	Client    *http.Client
}

// NewRemoteCalendar creates a RemoteCalendar with default settings.
func NewRemoteCalendar(calURL string) *RemoteCalendar {
	return &RemoteCalendar{
		URL:       calURL,
		UserAgent: "go-opentimestamps",
		Client:    &http.Client{Timeout: defaultTimeout},
	}
}

func (rc *RemoteCalendar) headers() map[string]string {
	return map[string]string{
		"Accept":     "application/vnd.opentimestamps.v1",
		"User-Agent": rc.UserAgent,
	}
}

func (rc *RemoteCalendar) doRequest(req *http.Request) ([]byte, int, error) {
	for k, v := range rc.headers() {
		req.Header.Set(k, v)
	}
	resp, err := rc.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > maxResponseSize {
		return nil, resp.StatusCode, fmt.Errorf("calendar response exceeded size limit")
	}
	return body, resp.StatusCode, nil
}

// Submit sends a digest to the calendar and returns the resulting Timestamp.
func (rc *RemoteCalendar) Submit(digest []byte, timeout time.Duration) (*core.Timestamp, error) {
	client := rc.Client
	if timeout > 0 {
		client = &http.Client{Timeout: timeout}
	}

	calURL, err := url.JoinPath(rc.URL, "digest")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, calURL, bytes.NewReader(digest))
	if err != nil {
		return nil, err
	}
	for k, v := range rc.headers() {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("calendar response exceeded size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unknown response from calendar: %d", resp.StatusCode)
	}

	ctx := core.NewBytesDeserializationContext(body)
	return core.DeserializeTimestamp(ctx, digest, 256)
}

// GetTimestamp fetches a timestamp for a given commitment from the calendar.
// Returns CommitmentNotFoundError if the calendar returns 404.
func (rc *RemoteCalendar) GetTimestamp(commitment []byte, timeout time.Duration) (*core.Timestamp, error) {
	client := rc.Client
	if timeout > 0 {
		client = &http.Client{Timeout: timeout}
	}

	calURL, err := url.JoinPath(rc.URL, "timestamp", hex.EncodeToString(commitment))
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, calURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range rc.headers() {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 160))
		return nil, &CommitmentNotFoundError{Reason: sanitizeResponse(msg)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("calendar response exceeded size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unknown response from calendar: %d", resp.StatusCode)
	}

	ctx := core.NewBytesDeserializationContext(body)
	return core.DeserializeTimestamp(ctx, commitment, 256)
}

// sanitizeResponse replaces non-whitelisted characters with '_'.
func sanitizeResponse(raw []byte) string {
	const whitelist = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#-.,; "
	out := make([]byte, len(raw))
	for i, c := range raw {
		if strings.ContainsRune(whitelist, rune(c)) {
			out[i] = c
		} else {
			out[i] = '_'
		}
	}
	return string(out)
}

// --- UrlWhitelist ---

// UrlWhitelist is a glob-matching whitelist for calendar URLs.
// Patterns use fnmatch-style globs on the hostname only.
type UrlWhitelist struct {
	patterns []*url.URL
}

// NewUrlWhitelist creates a UrlWhitelist from a list of URL strings.
func NewUrlWhitelist(urls ...string) (*UrlWhitelist, error) {
	wl := &UrlWhitelist{}
	for _, u := range urls {
		if err := wl.Add(u); err != nil {
			return nil, err
		}
	}
	return wl, nil
}

// Add adds a URL pattern to the whitelist.
// If the URL has no scheme, it is added for both http and https.
func (wl *UrlWhitelist) Add(rawURL string) error {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if err := wl.Add("http://" + rawURL); err != nil {
			return err
		}
		return wl.Add("https://" + rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("whitelist URL must not have query or fragment: %s", rawURL)
	}
	wl.patterns = append(wl.patterns, u)
	return nil
}

// Contains reports whether rawURL is allowed by the whitelist.
func (wl *UrlWhitelist) Contains(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	for _, pattern := range wl.patterns {
		if u.Scheme == pattern.Scheme && u.Path == pattern.Path {
			if globMatch(pattern.Hostname(), u.Hostname()) {
				return true
			}
		}
	}
	return false
}

// globMatch implements fnmatch-style glob where '*' matches any sequence of
// characters including dots (matching Python's fnmatch behaviour).
func globMatch(pattern, host string) bool {
	if pattern == host {
		return true
	}
	idx := strings.Index(pattern, "*")
	if idx < 0 {
		return false
	}
	prefix := pattern[:idx]
	suffix := pattern[idx+1:]
	if !strings.HasPrefix(host, prefix) {
		return false
	}
	rest := host[len(prefix):]
	return strings.HasSuffix(rest, suffix)
}

// DefaultCalendarWhitelist is the default set of trusted calendar URLs.
var DefaultCalendarWhitelist, _ = NewUrlWhitelist(
	"https://*.calendar.opentimestamps.org",
	"https://*.calendar.eternitywall.com",
	"https://*.calendar.catallaxy.com",
)

// DefaultAggregators are the default aggregator URLs for stamp operations.
var DefaultAggregators = []string{
	"https://a.pool.opentimestamps.org",
	"https://b.pool.opentimestamps.org",
	"https://a.pool.eternitywall.com",
	"https://ots.btc.catallaxy.com",
}
