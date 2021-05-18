#!/usr/bin/env python3

from datetime import tzinfo, timedelta, datetime
import os
import sys
import json
import dns.resolver
import falcon

class QuoteResource:

    def on_get(self, req, resp):
        """Handles GET requests"""
        quote = {
            'quote': (
                "I've always been more interested in "
                "the future than in the past."
            ),
            'author': 'Grace Hopper'
        }

        resp.media = quote


class DNSResolver:

    def on_post(self, req, resp):
        if req.content_length in (None, 0):
            # Nothing to do
            return

        body = req.stream.read()

        print(body)
#        posted_data = json.loads(req.stream.read())
        resp.status = falcon.HTTP_200  # This is the default status

#        answers = None
#        q_dt = datetime.utcnow()
#        resolver = dns.resolver.Resolver()
#        resolver.timeout = 8
#        resolver.lifetime = 8
#        answers = resolver.query(fqdn, r_type)

#        posted_data = json.loads(req.stream.read())
#        print(posted_data)
#
#        resp.status = falcon.HTTP_200  # This is the default status
#        resp.content_type = falcon.MEDIA_TEXT  # Default is JSON, so override
#        resp.text = ('\nTwo things awe me most, the starry sky '
#                     'above me and the moral law within me.\n'
#                     '\n'
#                     '    ~ Immanuel Kant\n\n')
#        return 200

