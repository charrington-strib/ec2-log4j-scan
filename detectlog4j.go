package main

import (
	"fmt"

	"github.com/ironiridis/util/env"
)

var matchlog4j = env.GetRegexp("JAVA_LOG4J_DETECT", "(?m:^Log4jReleaseVersion:\\s+2\\.([0-9]\\b|1[0-5]\\b))")

func (h *Host) DetectVulnerableLog4j2() (bool, error) {
	stdout, stderr, err := h.Run("/usr/bin/sudo -- find / -xdev -name '*.jar' -exec unzip -a -c {} 'META-INF/MANIFEST.MF' ';'")
	res := matchlog4j.Match(stdout)
	if err != nil {
		if len(stderr) > 0 {
			return res, fmt.Errorf("detection failed with output %q and error %w", stderr, err)
		}
		return res, fmt.Errorf("detection failed with error %w", err)
	}
	return res, nil
}
