# Stress tests

Tests which run `mpa.communication.client.Client` from many threads against
real forwarder built from `../message_router`. They are not collected by plain
`pytest` in `code/` (see `testpaths` in `pyproject.toml`), because they need
C++ toolchain and libraries which normal unit test environment lacks.

Each scenario (see `client_scenarios.py`) runs in a separate spawned process,
as sockets used from two threads at once may abort the process inside libzmq.
In that process all zmq sockets are replaced with `CheckingSocket`, which raises
instead of entering libzmq when a socket is used by a second thread while
another one still uses it, so races are detected even if they would not crash
or corrupt messages in given run.

## Running from checkout

Prerequisites: `make`, `g++`, libzmq (with headers), cppzmq (`zmq.hpp`),
boost program_options, plus python environment of `code/` (e.g. `uv sync --all-extras`).
On Debian: `apt install build-essential libzmq3-dev cppzmq-dev libboost-program-options-dev`.

```
cd code
uv run pytest stress_tests
```

Forwarder is built into `stress_tests/.build` (sources are copied there, so
checkout stays clean, and only changed files are rebuilt in next runs).
Environment variables:

* `MPA_TEST_FORWARDER` --- use already built forwarder binary instead of building it
* `MPA_FORWARDER_BUILD_DIR` --- build forwarder in other directory
* `MPA_FORWARDER_MAKE_ARGS` --- extra arguments for make, e.g. to use headers and libraries from yocto sysroot:
  `MPA_FORWARDER_MAKE_ARGS="wxcflags=-idirafter/path/to/include wxldflags=-no-pie ldflags='-lzmq /path/to/libboost_program_options.a -lstdc++fs'"`

## Running in docker

From repository root:

```
docker build -t mpa-stress-tests -f code/stress_tests/Dockerfile code
docker run --rm -v "$PWD/code:/work" mpa-stress-tests
```

Image contains only dependencies, sources are taken from mounted checkout, so
image needs to be rebuilt only when dependencies change. Additional pytest
arguments can be given by overriding the command, e.g.
`docker run ... mpa-stress-tests /opt/venv/bin/python -m pytest -p no:cacheprovider stress_tests -k queries`.

Tests do not write to the mounted checkout (bytecode and pytest cache are
disabled, forwarder is built in `/tmp`), so container can run as root. Do not
use `--user` with uid/gid unknown to the image --- forwarder needs entry of its
group in group database (otherwise it crashes).
