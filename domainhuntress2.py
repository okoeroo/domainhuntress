from datetime import tzinfo, timedelta, datetime

import falcon
import falcon.asgi

import dns.resolver
import dns.message
import dns.asyncquery
import dns.asyncresolver


# Falcon follows the REST architectural style, meaning (among
# other things) that you think in terms of resources and state
# transitions, which map to HTTP verbs.
class DNSHuntress:
    def __init__(self, resolvers=["127.0.0.1"]):
        # a list
        self.resolvers = resolvers

    async def on_get(self, req, resp):
        """Handles GET requests"""
        resp.status = falcon.HTTP_200  # This is the default status
        resp.content_type = falcon.MEDIA_TEXT  # Default is JSON, so override
        resp.text = ('\nTwo things awe me most, the starry sky '
                     'above me and the moral law within me.\n'
                     '\n'
                     '    ~ Immanuel Kant\n\n')

    async def on_post(self, req, resp):
        if req.content_length in (None, 0):
            # Nothing to do
            return

        if 'application/json' != req.content_type:
            resp.status = falcon.HTTP_415
            return

        print(req.content_type)

        deserialized_media = await req.get_media()
        print(deserialized_media)

        print(deserialized_media['fqdn'])
        print(deserialized_media['type'])

        print("goto self._dns_query")
        answer = await self._dns_query(deserialized_media['fqdn'], deserialized_media['type'])
        print(answer)

        resp.text = str(answer)
        resp.status = falcon.HTTP_201

    async def _dns_query(self, fqdn, r_type):
        print("dns_query", fqdn, r_type)

        ### DNS Resolve FQDN with resource type
        answers = None
        q_dt = datetime.utcnow()

        try:
            print("resolve")
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.resolvers
            resolver.timeout = 8
            resolver.lifetime = 8
            answer = resolver.resolve(fqdn, r_type)
            a_dt = datetime.utcnow()
            #for i in answer:
            #    print(i)

            d = {}
            d['q_dt'] = str(q_dt)
            d['a_dt'] = str(a_dt)
            d['canonical_name'] = answer.canonical_name.to_text()
            d['covers'] = dns.rdatatype.to_text(answer.covers)
            d['expiration'] = answer.expiration
            d['qname'] = answer.qname.to_text()
            d['rdataclass'] = dns.rdataclass.to_text(answer.rdclass)
            d['rdatatype'] = dns.rdatatype.to_text(answer.rdtype)
            d['ttl'] = dns.ttl.make(answer.ttl)

            d['rdataset'] = []
            for rr in answer:
                e = {}
                e['rdata'] = rr.to_text()
                d['rdataset'].append(e)

            return d

        except dns.resolver.NXDOMAIN:
            print("Resolver warning: NXDOMAIN.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
            pass
        except dns.resolver.NoAnswer:
            print("Resolver warning: SERVFAIL.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
            pass
        except dns.exception.Timeout:
            print("Resolver error: Time out reached.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
        except EOFError:
            print("Resolver error: EOF Error.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

        except Exception as e:
            print("Resolver error:", e, 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)

        return None


### MAIN ###
app = falcon.asgi.App()
dns_huntress = DNSHuntress(["192.168.1.2"])

app.add_route('/huntress/dns/query', dns_huntress)
app.add_route('/huntress/dns2/{user_id}', dns_huntress)

