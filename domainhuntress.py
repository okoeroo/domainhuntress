#!/usr/bin/env python3

from datetime import tzinfo, timedelta, datetime
import os
import sys


import falcon
import falcon_jsonify
from wsgiref import simple_server


from domainhuntress import dh_args, dh_dns



### Main
if __name__ == "__main__":
    # Init
    args = dh_args.DHParseArgs(__file__)

    # Bootstrap Falcon
    app = application = falcon.App(middleware=[falcon_jsonify.Middleware(help_messages=True),])

    # Start
    app = application = falcon.App()

    # Routing
    app.add_route('/domainhuntress', dh_dns.QuoteResource())
    print("Loaded route: '/domainhuntress'")

    # Serving
    try:
        httpd = simple_server.make_server(args.host, args.port, app)
    except:
        print("Can't bind interface to", args.host, args.port, "possibly already in use")
        sys.exit(1)

    print("Operating on", args.host, "port", args.port, "from current working dir", args.chroot)
    print("Locked and loaded for the hunt!")
    httpd.daemon_threads = True

    try:
        httpd.serve_forever()

    except KeyboardInterrupt:
        print("Service stopped by user.")
        pass
