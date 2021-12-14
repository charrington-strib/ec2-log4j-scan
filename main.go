package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

func main() {
	var HostList []Host
	um := json.NewDecoder(os.Stdin)
	err := um.Decode(&HostList)
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	hostch := make(chan *Host)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			var res bool
			var err error
			defer wg.Done()
			for h := range hostch {
				// first-pass cheap scan of /proc for anything that looks like a java runtime
				res, err = h.DetectJavaMaybe()
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to check instance %q: %v\n", h.InstanceID, err)
				}
				if !res {
					continue
				}
				fmt.Fprintf(os.Stdout, " * %q/%q -- Detected JVM\n", h.InstanceID, h.Hostname)
				// second-pass full disk scan for jar files, extracting manifests looking for log4j versions
				res, err = h.DetectVulnerableLog4j2()
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to scan JVM instance %q for vulnerable jar files: %v", h.InstanceID, err)
				}
				if !res {
					fmt.Fprintf(os.Stdout, " * %q/%q -- no vulnerable log4j detected\n", h.InstanceID, h.Hostname)
					continue
				}
				fmt.Fprintf(os.Stdout, " !! %q/%q -- Detected vulnerable log4j\n", h.InstanceID, h.Hostname)
			}
		}()
	}

	for i := range HostList {
		if HostList[i].Usable() {
			hostch <- &HostList[i]
		}
	}
	close(hostch)
	wg.Wait()
}
