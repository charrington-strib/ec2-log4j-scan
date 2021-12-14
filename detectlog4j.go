package main

import (
	"fmt"

	"github.com/ironiridis/util/env"
)

var matchlog4j = env.GetRegexp("JAVA_LOG4J_DETECT", "(?m:^Log4jReleaseVersion:\\s+2\\.([0-9]\\b|1[0-5]\\b))")

func (h *Host) DetectVulnerableLog4j2() (bool, error) {
	out, err := h.Run("/usr/bin/sudo -- find / -xdev -name '*.jar' -exec unzip -a -c {} 'META-INF/MANIFEST.MF' ';'")
	if err != nil {
		if len(out) > 0 {
			return false, fmt.Errorf("detection failed with output %q and error %w", out, err)
		}
		return false, fmt.Errorf("detection failed with error %w", err)
	}
	return matchlog4j.Match(out), nil
}
