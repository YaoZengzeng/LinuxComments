//+build !windows

package daemon

import (
	"github.com/docker/docker/container"
)

func (daemon *Daemon) saveApparmorConfig(container *container.Container) error {
	container.AppArmorProfile = "" //we don't care about the previous value.

	// 如果daemon不支持apparmor，则什么都不做
	if !daemon.apparmorEnabled {
		return nil // if apparmor is disabled there is nothing to do here.
	}

	if err := parseSecurityOpt(container, container.HostConfig); err != nil {
		return validationError{err}
	}

	if !container.HostConfig.Privileged {
		if container.AppArmorProfile == "" {
			container.AppArmorProfile = defaultApparmorProfile
		}

	} else {
		// 如果HostConfig.Privileged为true，则将AppArmorProfile设置为"unconfined"
		container.AppArmorProfile = "unconfined"
	}
	return nil
}
