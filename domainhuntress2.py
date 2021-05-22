#!/usr/bin/env python3

from datetime import tzinfo, timedelta, datetime
import argparse

import os
import sys
import json
import binascii
import falcon
import falcon.asgi
import uvicorn

import dns.resolver
import dns.message
import dns.asyncquery
import dns.asyncresolver

from ipwhois.net import Net
from ipwhois.asn import IPASN


def check_correctness(args):
#        parser.print_help()
    return True


def argparsing(exec_file):
    parser = argparse.ArgumentParser(exec_file)
    parser.add_argument("--lhost",
                        dest='lhost',
                        help="The listening host, default: 127.0.0.1.",
                        default="127.0.0.1",
                        type=str)
    parser.add_argument("--resolver",
                        dest='resolver',
                        help="The default resolver is 127.0.0.1",
                        default="127.0.0.1",
                        type=str)
    parser.add_argument("--lport",
                        dest='lport',
                        help="Listening port",
                        default='lport',
                        type=str)
    parser.add_argument("--log-level",
                        choices=['info'],
                        dest='log_level',
                        help="Log levels",
                        default='info',
                        type=str)

    args = parser.parse_args()
    if not check_correctness(args):
        return None

    return args

def dequote(s):
    if s.startswith("'") or s.startswith("\""):
        s = s[1:]
    if s.endswith("'") or s.endswith("\""):
        s = s[:-1]
    return s

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
        d = None

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
                e['rdata'] = dequote(rr.to_text())
                expansion = await self._dns_query_expansion(qname, r_type, e['rdata'], rr)
                if expansion is not None:
                    e['rdata_e'] = expansion

                d['rdataset'].append(e)

            print(d)
            return d

        except dns.resolver.NXDOMAIN:
            print("Resolver warning: NXDOMAIN.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)
            a_dt = datetime.utcnow()

            d = {}
            d['q_dt'] = str(q_dt)
            d['a_dt'] = str(a_dt)
            d['error'] = 'NXDOMAIN'

            pass
        except dns.resolver.NoAnswer:
            print("Resolver warning: NoAnswer.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)
            a_dt = datetime.utcnow()

            d = {}
            d['q_dt'] = str(q_dt)
            d['a_dt'] = str(a_dt)
            d['error'] = 'NoAnswer'

            pass
        except dns.resolver.SERVFAIL:
            print("Resolver warning: SERVFAIL.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)
            a_dt = datetime.utcnow()

            d = {}
            d['q_dt'] = str(q_dt)
            d['a_dt'] = str(a_dt)
            d['error'] = 'SERVFAIL'

            pass
        except dns.exception.Timeout:
            print("Resolver error: Time out reached.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)
        except EOFError:
            print("Resolver error: EOF Error.", 'FQDN', qname, 'r_type', r_type, file=sys.stderr)

        except Exception as e:
            print("Resolver error:", e, 'FQDN', qname, 'r_type', r_type, file=sys.stderr)

        return d


    async def _dns_query_expansion(self, qname, rtype, rdata, rr):
        if rtype == 'CNAME':
            r = {}
            r['cname'] = await self._dns_query(rdata, 'CNAME')
            return r

        elif rtype == 'SOA':
            r = {}
            r['mname'] = rr.mname.to_text()
            r['rname'] = rr.rname.to_text()
            r['serial'] = str(rr.serial)
            r['refresh'] = str(rr.refresh)
            r['retry'] = str(rr.retry)
            r['expire'] = str(rr.expire)
            r['minimum'] = str(rr.minimum)
            return r

        elif rtype == 'TLSA':
            r = {}
            r['usage'] = str(rr.usage)
            r['selector'] = str(rr.selector)
            r['mtype'] = str(rr.mtype)
            r['cert'] = rr.cert.hex()
            return r

        elif rtype == 'MX':
            r = {}
            r['preference'] = str(rr.preference)
            r['exchange'] = rr.exchange.to_text()
            return r

        elif rtype == 'TXT':
            rdata_deq = dequote(rdata)

            # SPF
            if rdata_deq.lower().startswith('v=spf1'):
                r = []
                for i in rdata_deq.split():
                    # Expand MX
                    if i.lower() == 'mx':
                        mx_e = {}
                        mx_e['mx'] = await self._dns_query(qname, 'MX')

                        r.append(mx_e)
                    # Expand A
                    elif i.lower() == 'a':
                        a_e = {}
                        a_e['a'] = await self._dns_query(qname, 'A')

                        r.append(a_e)
                    # Expand AAAA
                    elif i.lower() == 'aaaa':
                        aaaa_e = {}
                        aaaa_e['aaaa'] = await self._dns_query(qname, 'AAAA')

                        r.append(aaaa_e)
                    # Expand include
                    elif i.lower().startswith('include'):
                        include_e = {}
                        include_target = i.split(":")[1]
                        if len(include_target) == 0:
                            # Formatting problem found of include element. Just adding it raw
                            r.append(i)
                        else:
                            # Key is: current record, as is
                            include_e[i.lower()] = await self._dns_query(include_target, 'TXT')
                            r.append(include_e)
                    # Expand redirect
                    elif i.lower().startswith('redirect'):
                        redirect_e = {}
                        redirect_target = i.split("=")[1]
                        if len(redirect_target) == 0:
                            # Formatting problem found of redirect element. Just adding it raw
                            r.append(i)
                        else:
                            # Key is: current record, as is
                            redirect_e[i.lower()] = await self._dns_query(redirect_target, 'TXT')
                            r.append(redirect_e)
                    else:
                        r.append(i)
                return r

            # DMARC
            elif rdata_deq.lower().startswith('v=dmarc1'):
                r = {}
                for i in rdata_deq.split(';'):
                    t = i.strip()
                    if t == '':
                        continue

                    r[t.split("=")[0]] = t.split("=")[1]
                return r

            # TLSRPTv1
            elif rdata_deq.lower().startswith('v=TLSRPTv1'.lower()):
                r = {}
                for i in rdata_deq.split(';'):
                    t = i.strip()
                    if t == '':
                        continue

                    r[t.split("=")[0]] = t.split("=")[1]
                return r


        elif rtype == 'CAA':
            rdata_deq = dequote(rdata)
            r = []
            for i in rdata_deq.split():
                r.append(i)
            return r

        return None



### MAIN ###
app = falcon.asgi.App()
whois_huntress = WhoisHuntress()
dns_huntress = DNSHuntress(["192.168.1.2"])

app.add_route('/huntress/whois/query', whois_huntress)
app.add_route('/huntress/dns/query', dns_huntress)
app.add_route('/huntress/dns2/{user_id}', dns_huntress)

if __name__ == "__main__":
    # Init
    args = argparsing(os.path.basename(__file__))
    app_name = os.path.basename(__file__).split(".")[0] + ":app"

    if args is None:
        raise Exception("error in arguments")

    uvicorn.run(app_name, host="127.0.0.1", port=8000, log_level="info", workers=4)
