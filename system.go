/*
	date: 2015-04-21
	author: xjdrew
*/
package main

import (
	"net/http"
	"os/exec"
	"strconv"
	"strings"
)

func runCmd(script string, mode string, target string, port int) error {
	script = strings.Replace(script, "$MODE$", mode, -1)
	script = strings.Replace(script, "$TARGET$", target, -1)
	script = strings.Replace(script, "$PORT$", strconv.Itoa(port), -1)
	var cmd *exec.Cmd
	cmd = exec.Command("/bin/sh", "-c", script)
	return cmd.Run()
}

func requestUrl(url string, mode string, target string, port int) error {
	url = strings.Replace(url, "$MODE$", mode, -1)
	url = strings.Replace(url, "$TARGET$", target, -1)
	url = strings.Replace(url, "$PORT$", strconv.Itoa(port), -1)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
