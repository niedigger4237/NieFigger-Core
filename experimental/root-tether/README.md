# Experimental ROOT TUN hot refresh

Pinned sing-tun: bca4bf029237e444104626bb25f947dda90b06b5 (the version selected by the existing core).

This branch is intentionally **not** used by the standard core build or the app. The planner reuses sing-tun's actual route/rule generators, preserves the immutable effective route exclusions (including SRS), and rejects changes to anything other than exact downstream selectors and explicitly tracked local prefixes. It does not modify live kernel state. Run `bash experimental/root-tether/check.sh` on a Linux Go builder with GitHub access.

The next stage must implement ownership-verified netlink operations, serialized with native TUN close and Android VPN callbacks, exact rollback and acknowledgement, then integrate with the app's existing forwarding exceptions and IPv6 guard. Do not use the existing UpdateRouteOptions as a substitute: it replaces routes but not interface policy rules. The current startup and restart fallback stay unchanged until device testing validates the new transaction.
