from datetime import tzinfo, timedelta, datetime

import sys
import json
import falcon
import falcon.asgi

import dns.resolver
import dns.message
import dns.asyncquery
import dns.asyncresolver

from ipwhois.net import Net
from ipwhois.asn import IPASN


class WhoisHuntress:
    async def on_post(self, req, resp):
        if req.content_length in (None, 0):
            # Nothing to do
            return

        if 'application/json' != req.content_type:
            resp.status = falcon.HTTP_415
            return

        deserialized_media = await req.get_media()
        print(deserialized_media)

        
        try:
            q_dt = datetime.utcnow()
            answer = await self._dns_whois(deserialized_media['ipaddress'])
            a_dt = datetime.utcnow()

            print(answer)

            answer['q_dt'] = str(q_dt)
            answer['a_dt'] = str(a_dt)


            resp.text = json.dumps(answer)
            resp.status = falcon.HTTP_201
        except Exception as e:
            print(e)

    async def _dns_whois(self, ipaddress):
        net = Net(ipaddress)
        obj = IPASN(net)
        results = obj.lookup()

        return results


# Falcon follows the REST architectural style, meaning (among
# other things) that you think in terms of resources and state
# transitions, which map to HTTP verbs.
class DNSHuntress:
    def __init__(self, resolvers=["127.0.0.1"]):
        # a list
        self.resolvers = resolvers

    async def on_post(self, req, resp):
        if req.content_length in (None, 0):
            # Nothing to do
            return

        if 'application/json' != req.content_type:
            resp.status = falcon.HTTP_415
            return

        try:
            deserialized_media = await req.get_media()

            answer = await self._dns_query(deserialized_media['fqdn'], deserialized_media['type'])

            resp.text = json.dumps(answer)
            resp.status = falcon.HTTP_201

        except Exception as e:
            print(e)

    async def _dns_query(self, qname, r_type):
        print("dns_query", qname, r_type)

        ### DNS Resolve FQDN with resource type
        answer = None
        q_dt = datetime.utcnow()

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.resolvers
            resolver.timeout = 8
            resolver.lifetime = 8
            answer = resolver.resolve(qname, r_type)
            a_dt = datetime.utcnow()

            print(answer)
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
            d['ttl'] = str(answer.ttl)

            d['rdataset'] = []
            for rr in answer:
                e = {}
                e['rdata'] = rr.to_text()
                expansion = self._dns_query_expansion(qname, r_type, e['rdata'], rr) 
                if expansion is not None:
                    e['rdata_e'] = expansion
                
                d['rdataset'].append(e)

            print(d)
            return d

        except dns.resolver.NXDOMAIN:
            print("Resolver warning: NXDOMAIN.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)
            pass
        except dns.resolver.NoAnswer:
            print("Resolver warning: SERVFAIL.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)
            pass
        except dns.exception.Timeout:
            print("Resolver error: Time out reached.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)
        except EOFError:
            print("Resolver error: EOF Error.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)

        except Exception as e:
            print("Resolver error:", e, 'FQDN', qname, 'r_type', r_type, file=sys.stderr)

        return None

    def _dns_query_expansion(self, qname, r_type, rdata, rr):
        if r_type == 'MX':
            print(rr.preference)
            print(rr.exchange)
            r = {}
            r['preference'] = str(rr.preference)
            r['exchange'] = rr.exchange.to_text()
            return r
        
        return None




### MAIN ###
app = falcon.asgi.App()
whois_huntress = WhoisHuntress()
dns_huntress = DNSHuntress(["192.168.1.2"])

app.add_route('/huntress/whois/query', whois_huntress)
app.add_route('/huntress/dns/query', dns_huntress)
app.add_route('/huntress/dns2/{user_id}', dns_huntress)

