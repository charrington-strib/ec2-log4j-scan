package main

import (
	"fmt"

	"github.com/ironiridis/util/env"
)

var matchjrebin = env.GetRegexp("JAVA_BINARY_DETECT", "(?i:java|jvm|jre|jdk|icedtea|hotspot|classpath|tomcat)")

func (h *Host) DetectJavaMaybe() (bool, error) {
	stdout, stderr, err := h.Run(
		"/usr/bin/sudo -- " +
			"find /proc -ignore_readdir_race -xdev -maxdepth 2 -mindepth 2 " +
			"-type l -xtype f -name 'exe' -executable -printf '%l\\n'")
	res := matchjrebin.Match(stdout)
	if err != nil {
		if len(stderr) > 0 {
			return res, fmt.Errorf("detection failed with output %q and error %w", stderr, err)
		}
		return res, fmt.Errorf("detection failed with error %w", err)
	}
	return res, nil
}
