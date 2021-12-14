package main

import "testing"

func TestShouldMatchVulnerableVersions(t *testing.T) {
	c := []string{
		"Log4jReleaseVersion: 2.0-alpha1",
		"Log4jReleaseVersion: 2.0-alpha2",
		"Log4jReleaseVersion: 2.0-beta1",
		"Log4jReleaseVersion: 2.0-beta2",
		"Log4jReleaseVersion: 2.0-beta3",
		"Log4jReleaseVersion: 2.0-beta4",
		"Log4jReleaseVersion: 2.0-beta5",
		"Log4jReleaseVersion: 2.0-beta6",
		"Log4jReleaseVersion: 2.0-beta7",
		"Log4jReleaseVersion: 2.0-beta8",
		"Log4jReleaseVersion: 2.0-beta9",
		"Log4jReleaseVersion: 2.0-rc1",
		"Log4jReleaseVersion: 2.0-rc2",
		"Log4jReleaseVersion: 2.0.1",
		"Log4jReleaseVersion: 2.0.2",
		"Log4jReleaseVersion: 2.0",
		"Log4jReleaseVersion: 2.1",
		"Log4jReleaseVersion: 2.10.0",
		"Log4jReleaseVersion: 2.11.0",
		"Log4jReleaseVersion: 2.11.1",
		"Log4jReleaseVersion: 2.11.2",
		"Log4jReleaseVersion: 2.12.0",
		"Log4jReleaseVersion: 2.12.1",
		"Log4jReleaseVersion: 2.13.0",
		"Log4jReleaseVersion: 2.13.1",
		"Log4jReleaseVersion: 2.13.2",
		"Log4jReleaseVersion: 2.13.3",
		"Log4jReleaseVersion: 2.14.0",
		"Log4jReleaseVersion: 2.14.1",
		"Log4jReleaseVersion: 2.15.0",
		"Log4jReleaseVersion: 2.2",
		"Log4jReleaseVersion: 2.3",
		"Log4jReleaseVersion: 2.4.1",
		"Log4jReleaseVersion: 2.4",
		"Log4jReleaseVersion: 2.5",
		"Log4jReleaseVersion: 2.6.1",
		"Log4jReleaseVersion: 2.6.2",
		"Log4jReleaseVersion: 2.6",
		"Log4jReleaseVersion: 2.7",
		"Log4jReleaseVersion: 2.8.1",
		"Log4jReleaseVersion: 2.8.2",
		"Log4jReleaseVersion: 2.8",
		"Log4jReleaseVersion: 2.9.0",
		"Log4jReleaseVersion: 2.9.1",
	}
	for i := range c {
		if !matchlog4j.MatchString(c[i]) {
			t.Errorf("Failed to match version string %q", c[i])
		}
		if !matchlog4j.MatchString("\n" + c[i]) {
			t.Errorf("Failed to match version string %q", c[i])
		}
		if !matchlog4j.MatchString("\r\n" + c[i]) {
			t.Errorf("Failed to match version string %q", c[i])
		}
		if !matchlog4j.MatchString(c[i] + "\n") {
			t.Errorf("Failed to match version string %q", c[i])
		}
		if !matchlog4j.MatchString(c[i] + "\r\n") {
			t.Errorf("Failed to match version string %q", c[i])
		}
		if !matchlog4j.MatchString("\n" + c[i] + "\r\n") {
			t.Errorf("Failed to match version string %q", c[i])
		}
		if !matchlog4j.MatchString("\r\n" + c[i] + "\r\n") {
			t.Errorf("Failed to match version string %q", c[i])
		}

	}
}
