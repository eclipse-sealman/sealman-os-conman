# sealman-os-conman

**OS Configuration Layer** for the [Eclipse SEALMAN](https://projects.eclipse.org/projects/technology.sealman) project.

This repository (`sealman-os-conman`) contains the on-device OS components, written in **Python** and **Go**, responsible for connectivity and system management.

## Key Components

| Module | Description |
|---|---|
| `mpa` (Python) | Core library — networking, firewall, device, docker, VPN, SSH, web GUI, software updates |
| `nm` / `wifi` (Go) | NetworkManager and Wi-Fi integration |
| `mgmtd` (Go) | Management daemon |
| `message_router` (Go) | Inter-process message routing via D-Bus |

## Requirements

- Python ≥ 3.12
- Go ≥ 1.25
- System libraries: `libgirepository`, `libzmq`, `libarchive`, `libsystemd`, `libtss2`, `libcairo`

## Getting Started

Install the Python package:

```bash
pip install .
```

Build the Go components:

```bash
go build ./...
```

Run tests:

```bash
pytest
```

## License

Licensed under the [Eclipse Public License 2.0](LICENSE).  
Part of the [Eclipse SEALMAN](https://github.com/eclipse-sealman) project.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributors must sign the [Eclipse Contributor Agreement (ECA)](https://www.eclipse.org/legal/ECA.php).
