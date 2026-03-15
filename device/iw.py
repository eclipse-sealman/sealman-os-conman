#!/usr/bin/env python3
import sys

import pyroute2

if __name__ == "__main__":
    with pyroute2.IW() as iw:
        match sys.argv:
            case [_, "set", alpha2]:
                regdom = alpha2.strip()
                iw.set_regulatory_domain(regdom)
            case _:
                print("use set <alpha2>", file=sys.stderr)
                sys.exit(1)
