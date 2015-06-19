#!/usr/bin/env python3
# coding=utf-8
"""
 Copyright (c) 2015, NetIDE Consortium (Create-Net (CN), Telefonica Investigacion Y Desarrollo SA (TID), Fujitsu
 Technology Solutions GmbH (FTS), Thales Communications & Security SAS (THALES), Fundacion Imdea Networks (IMDEA),
 Universitaet Paderborn (UPB), Intel Research & Innovation Ireland Ltd (IRIIL), Fraunhofer-Institut für
 Produktionstechnologie (IPT), Telcaria Ideas SL (TELCA) )

 All rights reserved. This program and the accompanying materials
 are made available under the terms of the Eclipse Public License v1.0
 which accompanies this distribution, and is available at
 http://www.eclipse.org/legal/epl-v10.html

 Authors:
     Gregor Best, gbe@mail.upb.de
"""

# TODO:
# - [X] Read metadata
# - [X] Collect Apps
#   - Check parameter constraints (should always apply, but better be safe)
# - [X] Determine App->Controller mappings
# - [ ] For each app:
#   - [ ] Check system requirements
#     - [X] Hardware: CPU/RAM
#     - [ ] Installed Software: Java version? Controller software? ...?

# Package structure:
# _apps         # Network applications
#  \ _app1
#  | _app2
# _templates    # Templates for parameter and structure mapping
#  \ _template1
#  | _template2
# _system_requirements.json
# _topology_requirements.treq
# _parameters.json

import argparse
import fcntl
import inspect
import json
import os
import signal
import sys
import time

from loader import controllers
from loader import environment
from loader import topology
from loader.package import Package

# TODO: store {pids,logs} somewhere in /var/{run,log}
dataroot = "/tmp/netide"

class FLock(object):
    "Context manager for locking file objects with flock"
    def __init__(self, f, t=fcntl.LOCK_EX):
        self.f = f
        self.t = t

    def __enter__(self):
        fcntl.flock(self.f, self.t)
        return self.f

    def __exit__(self, exc_type, exc_value, traceback):
        fcntl.flock(self.f, fcntl.LOCK_UN)

def load_package(args):
    p = Package(args.package, dataroot)
    if not p.applies():
        print("There's something wrong with the package", file=sys.stderr)
        return 2

    os.makedirs(dataroot, exist_ok=True)

    with FLock(open(os.path.join(dataroot, "controllers.json"), "w+")) as f:
        try:
            data  = json.load(f)
        except ValueError:
            data = {}
        f.seek(0)
        f.truncate()
        try:
            pids = p.start()
            print(pids)
            data["controllers"] = pids
            json.dump(data, f, indent=2)
        except Exception as err:
            print(err)
            return 1
    return 0

def list_controllers(args):
    try:
        with FLock(open(os.path.join(dataroot, "controllers.json")), fcntl.LOCK_SH) as f:
            print(f.read())
        return 0
    except Exception as err:
        print(err, file=sys.stderr)
        return 1

def stop_controllers(args):
    with FLock(open(os.path.join(dataroot, "controllers.json"), "r+")) as f:
        try:
            d = json.load(f)
            for c in d["controllers"]:
                for pid in [p["pid"] for p in d["controllers"][c]["procs"]]:
                    try:
                        # TODO: gentler (controller specific) way of shutting down?
                        os.kill(pid, signal.SIGTERM)
                        print("Sent a SIGTERM to process {} for controller {}".format(pid, c), file=sys.stderr)
                        time.sleep(5)
                        os.kill(pid, signal.SIGKILL)
                        print("Sent a SIGKILL to process {} for controller {}".format(pid, c), file.sys.stderr)
                    except ProcessLookupError:
                        pass
            f.seek(0)
            f.truncate()
            del d["controllers"]
            json.dump(d, f)
        except KeyError:
            print("Nothing to stop", file=sys.stderr)
            return 0
        except Exception as err:
            print(err, file=sys.stderr)
            return 1
    return 0


def get_topology(args):
    print(topology.get())
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage NetIDE packages")
    subparsers = parser.add_subparsers()

    parser_load = subparsers.add_parser("load", description="Load a NetIDE package and start its applications")
    parser_load.add_argument("package", type=str, help="Package to load")
    parser_load.set_defaults(func=load_package)

    parser_list = subparsers.add_parser("list", description="List currently running NetIDE controllers")
    parser_list.set_defaults(func=list_controllers)

    parser_stop = subparsers.add_parser("stop", description="Stop all currently runnning NetIDE controllers")
    parser_stop.set_defaults(func=stop_controllers)

    parser_topology = subparsers.add_parser("gettopology", description="Show network topology")
    parser_topology.set_defaults(func=get_topology)

    args = parser.parse_args()
    if 'func' not in vars(args):
        parser.print_help()
        sys.exit(1)
    sys.exit(args.func(args))