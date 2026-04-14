// Copyright (C) 2024 The OpenTimestamps developers
//
// Go rewrite of python-opentimestamps.
// SPDX-License-Identifier: LGPL-3.0-or-later

package calendar_test

import (
	"testing"

	"github.com/opentimestamps/go-opentimestamps/calendar"
)

func TestUrlWhitelistEmpty(t *testing.T) {
	wl, _ := calendar.NewUrlWhitelist()
	if wl.Contains("") {
		t.Error("empty whitelist should not contain empty string")
	}
	if wl.Contains("http://example.com") {
		t.Error("empty whitelist should not contain any URL")
	}
}

func TestUrlWhitelistExactMatch(t *testing.T) {
	wl, err := calendar.NewUrlWhitelist("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !wl.Contains("https://example.com") {
		t.Error("should contain https://example.com")
	}
	if wl.Contains("http://example.com") {
		t.Error("should not contain http://example.com (wrong scheme)")
	}
	if wl.Contains("http://example.org") {
		t.Error("should not contain http://example.org")
	}
}

func TestUrlWhitelistGlob(t *testing.T) {
	wl, err := calendar.NewUrlWhitelist("*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !wl.Contains("https://foo.example.com") {
		t.Error("should match https://foo.example.com")
	}
	if !wl.Contains("http://bar.example.com") {
		t.Error("should match http://bar.example.com")
	}
	// Python fnmatch: * matches dots too
	if !wl.Contains("http://foo.bar.example.com") {
		t.Error("should match http://foo.bar.example.com")
	}
	if wl.Contains("http://barexample.com") {
		t.Error("should not match http://barexample.com")
	}
}

func TestUrlWhitelistContains(t *testing.T) {
	wl, err := calendar.NewUrlWhitelist(
		"https://*.calendar.opentimestamps.org",
		"https://*.calendar.eternitywall.com",
		"https://*.calendar.catallaxy.com",
	)
	if err != nil {
		t.Fatal(err)
	}

	allowed := []string{
		"https://alice.calendar.opentimestamps.org",
		"https://b.calendar.opentimestamps.org",
		"https://a.calendar.eternitywall.com",
		"https://a.calendar.catallaxy.com",
	}
	for _, u := range allowed {
		if !wl.Contains(u) {
			t.Errorf("expected %q to be in whitelist", u)
		}
	}

	denied := []string{
		"http://alice.calendar.opentimestamps.org",              // wrong scheme
		"https://evil.com",
		"https://alice.evil.com",
		"https://alice.calendar.opentimestamps.org/path?query=1", // has query
	}
	for _, u := range denied {
		if wl.Contains(u) {
			t.Errorf("expected %q NOT to be in whitelist", u)
		}
	}
}

func TestUrlWhitelistNoScheme(t *testing.T) {
	wl, err := calendar.NewUrlWhitelist("calendar.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !wl.Contains("http://calendar.example.com") {
		t.Error("should match http://")
	}
	if !wl.Contains("https://calendar.example.com") {
		t.Error("should match https://")
	}
}

func TestDefaultWhitelist(t *testing.T) {
	wl := calendar.DefaultCalendarWhitelist
	if !wl.Contains("https://a.calendar.opentimestamps.org") {
		t.Error("default whitelist should contain a.calendar.opentimestamps.org")
	}
	if !wl.Contains("https://alice.calendar.eternitywall.com") {
		t.Error("default whitelist should contain alice.calendar.eternitywall.com")
	}
}
