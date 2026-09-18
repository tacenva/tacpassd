package app

import (
	"runtime/debug"
	"strings"
)

func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	var (
		tag      string
		modified string
	)

	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.tag":
			tag = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}

	tag = strings.TrimSpace(tag)

	if tag == "" {
		return "dev"
	}

	if modified == "true" {
		return tag + "-dirty"
	}

	return tag
}
