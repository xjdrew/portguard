/*
	date: 2015-04-21
	author: xjdrew
*/
package main

import (
	"os/exec"
	"strconv"
	"strings"
)

func runCmd(script string, target string, port int) error {
	script = strings.Replace(script, "$TARGET$", target, -1)
	script = strings.Replace(script, "$PORT$", strconv.Itoa(port), -1)
	var cmd *exec.Cmd
	cmd = exec.Command("/bin/sh", "-c", script)
	return cmd.Run()
}
