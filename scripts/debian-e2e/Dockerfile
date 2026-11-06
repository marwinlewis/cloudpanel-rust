# A Debian 13 machine with real systemd, for testing the panel end to end. See run.sh.
FROM debian:13

ENV container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates curl \
      python3 procps iproute2 openssl \
 && rm -rf /var/lib/apt/lists/*

# Things that can't work, or aren't wanted, inside a container.
RUN systemctl mask getty@tty1.service console-getty.service \
      systemd-udevd.service systemd-udev-trigger.service systemd-firstboot.service

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
