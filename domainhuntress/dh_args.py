#!/usr/bin/env python3

import os
import argparse


def DHParseArgs(reference_main):

    # Init
    CUR_PATH = os.path.dirname(os.path.realpath(reference_main)) + '/'

    # Parser
    parser = argparse.ArgumentParser(os.path.basename(reference_main))
    parser.add_argument("--port",
                        help="Listening port number (default is 5000)",
                        default=5000,
                        type=int)
    parser.add_argument("--host",
                        default="127.0.0.1",
                        help="Listening on IP-address (default is 127.0.0.1).",
                        type=str)
    parser.add_argument("--chroot",
                        default=CUR_PATH,
                        help=f"Change directory for execution. Default is the current directory, which is {CUR_PATH}",
                        type=str)
    args = parser.parse_args()
    return args
