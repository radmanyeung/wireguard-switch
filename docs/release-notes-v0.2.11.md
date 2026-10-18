# Wireguard Split Tunnel v0.2.11

In Bypass WireGuard mode, enabled Software Rules now learn public TCP/IPv4
destinations every two seconds and add VPN host routes. Include subprocesses
tracks observed descendants, including grandchildren, for every software rule.
Learning continues when Monitor is stopped. The Software Rules page displays
learned destination and child-process counts.

Learned destinations survive normal app restarts. Route cleanup records exact
interface, next-hop and metric information, preserves shared domain-rule needs,
and retains unverifiable legacy cleanup records rather than guessing ownership.
The selected active WireGuard tunnel is used; ambiguous tunnel selection pauses
new route installation.

Windows Monitor now retains each socket's source address, so an existing
physical-source connection is not relabeled VPN merely because a route changed.
Connections on another active WireGuard tunnel are shown as Unknown.

This is best-effort destination routing. The first connection may precede
discovery; UDP, IPv6 and very short-lived processes are not covered. Other apps
connecting to a learned IP share its route. Existing sessions may require a
reconnect. This feature does not provide a kill switch or fail-closed guarantee.

Validation includes regression tests, Release builds, code review, and an
explicit Windows live probe that learned a child destination, reconnected using
the WireGuard source, received an HTTPS response, and removed its test route
without restarting the WireGuard service. See software-routing-validation.md
for evidence and remaining limits.
