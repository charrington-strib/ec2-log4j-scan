package main

import (
	"fmt"

	"github.com/ironiridis/util/env"
)

var matchjrebin = env.GetRegexp("JAVA_BINARY_DETECT", "(?i:java|jvm|jre|jdk|icedtea|hotspot|classpath|tomcat)")

func (h *Host) DetectJavaMaybe() (bool, error) {
	out, err := h.Run("/usr/bin/sudo -- find /proc -maxdepth 2 -mindepth 2 -type l -xtype f -name 'exe' -exec readlink -vf {} +")
	if err != nil {
		if len(out) > 0 {
			return false, fmt.Errorf("detection failed with output %q and error %w", out, err)
		}
		return false, fmt.Errorf("detection failed with error %w", err)
	}
	return matchjrebin.Match(out), nil
}
