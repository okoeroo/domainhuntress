
# Create your models here.
RR_TYPES = [
    (1, 'A'),
    (2, 'NS'),
    (5, 'CNAME'),
    (6, 'SOA'),
    (12, 'PTR'),
    (13, 'HINFO'),
    (15, 'MX'),
    (16, 'TXT'),
    (17, 'RP'),
    (24, 'SIG'),
    (25, 'KEY'),
    (28, 'AAAA'),
    (29, 'LOC'),
    (33, 'SRV'),
    (35, 'NAPTR'),
    (36, 'KX'),
    (37, 'CERT'),
    (39, 'DNAME'),
    (43, 'DS'),
    (46, 'RRSIG'),
    (47, 'NSEC'),
    (48, 'DNSKEY'),
    (50, 'NSEC3'),
    (51, 'NSEC3PARAM'),
    (52, 'TLSA'),
    (65, 'HTTPS'),
    (257, 'CAA')
]

RR_CLASSES = [
    ('IN', 'Internet'),
    ('CH', 'Chaos'),
    ('HS', 'Hesiod')
]

SAN_TYPES = [
    ('DNS', 'DNS'),
    ('URI', 'URI'),
    ('IP', 'IP address'),
    ('EMAIL', 'Email address'),
    ('DNAME', 'Directory name'),
    ('OTHER', 'Other name')
]

CERT_TYPES = [
    ('EEC', 'End Entity Certificate'),
    ('ICA', 'Intermediate CA'),
    ('RCA', 'Root CA')
]

L4_PROTO = [
    ('TCP', 'TCP'),
    ('UDP', 'UDP'),
    ('SCTP', 'SCTP')
]

class Certificate(models.Model):
    cert_dt         = models.DateTimeField(auto_now=True,blank=True)
    cert_not_before = models.DateTimeField(null=True, blank=True)
    cert_not_after  = models.DateTimeField(null=True, blank=True)
    cert_subject_dn = models.CharField(max_length=1024)
    cert_issuer_dn  = models.CharField(max_length=1024)
    cert_type       = models.CharField(max_length=32, choices=CERT_TYPES, default='EEC')

    cert_signed_by  = models.ForeignKey("self", on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        for item in CERT_TYPES:
            if item[0] == self.cert_type:
                c_t = item[1]
                break

        return "%s (%s)" % (self.cert_subject_dn, c_t)


class CertificateSAN(models.Model):
    cert_san_dt     = models.DateTimeField(auto_now=True,blank=True)
    cert_san_type   = models.CharField(max_length=32, choices=SAN_TYPES, default='DNS')
    cert_san        = models.CharField(max_length=255)

    cert            = models.ForeignKey(to=Certificate, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return "%s (%s)" % (self.cert_san, cert_san_type)


class HTTPRedirect(models.Model):
    http_redirect_dt = models.DateTimeField(auto_now=True,blank=True)
    http_redirect_url = models.CharField(max_length=1024)

    redirect = models.ForeignKey("self", on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return "%s" % self.http_redirect_url


class AutonomousSystem(models.Model):
    as_dt           = models.DateTimeField(auto_now=True,blank=True)
    as_number       = models.IntegerField()
    as_description  = models.CharField(max_length=255)
    as_date         = models.DateTimeField(null=True, blank=True)
    as_registry     = models.CharField(max_length=255)
    as_country_code = models.CharField(max_length=255)

    def __str__(self):
        return "asn: %d desc: %s" % (self.as_number, self.as_description)


class CIDRAddress(models.Model):
    cidr_dt = models.DateTimeField(auto_now=True,blank=True)
    cidr_addr = models.CharField(max_length=38)

    asn = models.ForeignKey(to=AutonomousSystem, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return "%s" % self.cidr_addr


class InternetAddress(models.Model):
    ip_dt = models.DateTimeField(auto_now=True,blank=True)
    ip_addr = models.CharField(max_length=38)

    cidr = models.ForeignKey(to=CIDRAddress, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return "%s" % self.ip_addr


class IPGeoLocation(models.Model):
    geoip_dt        = models.DateTimeField(auto_now=True,blank=True)

    geoip_ip_addr   = models.ForeignKey(to=InternetAddress, on_delete=models.CASCADE, null=True, blank=True)

    geoip_city      = models.CharField(max_length=128)
    geoip_region    = models.CharField(max_length=128)
    geoip_country   = models.CharField(max_length=128)
    geoip_loc       = models.CharField(max_length=128)
    geoip_org       = models.CharField(max_length=256)
    geoip_postal    = models.CharField(max_length=64)
    geoip_timezone  = models.CharField(max_length=64, default='Zulu')

    def __str__(self):
        return "%s: %s, %s, %s" % (self.geoip_ip_addr, self.geoip_country, self.geoip_region, self.geoip_city)


class ServiceDiscovered(models.Model):
    serv_disco_dt       = models.DateTimeField(auto_now=True,blank=True)
    serv_disco_port     = models.IntegerField()
    serv_disco_proto    = models.CharField(max_length=6, choices=L4_PROTO, default='TCP')

    def __str__(self):
        return "%d (%s)", (self.serv_disco_port, self.serv_disco_proto)


class DnsQuery(models.Model):
    dns_query_dt = models.DateTimeField(auto_now=True,blank=True)

    dns_query_name      = models.CharField(max_length=255)
    dns_query_rr_type   = models.IntegerField(choices=RR_TYPES)
    dns_query_rr_class  = models.CharField(max_length=2, choices=RR_CLASSES, default='IN')

    def __str__(self):
        for item in RR_TYPES:
            if item[0] == self.dns_query_rr_type:
                rr_t = item[1]
                break

        for item in RR_CLASSES:
            if item[0] == self.dns_query_rr_class:
                rr_c = item[1]
                break

        return "%s %s %s" % (self.dns_query_name, rr_t, rr_c)


class ResourceRecord(models.Model):
    rr_dt = models.DateTimeField(auto_now=True,blank=True)

    rr_name = models.CharField(max_length=255, null=True) # Similar to: dns_query_name
    rr_type = models.IntegerField(choices=RR_TYPES)
    rr_class = models.CharField(max_length=2, choices=RR_CLASSES, default='IN')
    rr_ttl = models.IntegerField(default=3601) # in Seconds of left over validaty
    rr_data = models.CharField(max_length=255)

    dns_query = models.ForeignKey(to=DnsQuery, on_delete=models.CASCADE, null=True, blank=True)

    # Other linkages
    rr_with_ip_address = models.ForeignKey(to=InternetAddress, on_delete=models.DO_NOTHING, null=True, blank=True)

    def __str__(self):
        for item in RR_TYPES:
            if item[0] == self.rr_type:
                rr_t = item[1]
                break

        for item in RR_CLASSES:
            if item[0] == self.rr_class:
                rr_c = item[1]
                break

        return "%s: %s %s %d %s" % (self.rr_name, rr_t, rr_c, self.rr_ttl, self.rr_data)


SCAN_STATUS = [
    ('NEW',         'New'),
    ('SCHEDULED',   'Scheduled'),
    ('EXECUTING',   'Executing'),
    ('FINISHED',    'Finished'),
    ('ERROR',       'Error')
]

class Scan(models.Model):
    scan_dt        =  models.DateTimeField(auto_now=True,blank=True)
    scan_start_dt  =  models.DateTimeField(null=True, blank=True)
    scan_finish_dt =  models.DateTimeField(null=True, blank=True)

    scan_name       = models.CharField(max_length=255)
    scan_status     = models.CharField(max_length=32, choices=SCAN_STATUS, null=True, blank=True)

    def __str__(self):
        return "%s (%s)" % (self.scan_name, self.scan_dt.strftime('%Y-%m-%d %H:%M'))


class ScanTarget(models.Model):
    target = models.CharField(max_length=255)

    scan = models.ForeignKey(to=Scan, on_delete=models.CASCADE)

    def __str__(self):
        return "%s" % self.target


TRANSFORMATION_STATUS = [
    ('UNPROCESSED', 'Unprocessed'),
    ('EXECUTING',   'Executing'),
    ('DONE',        'Done'),
    ('ERROR',       'Error')
]

TRANSFORMATION_TYPES = [
    ('TARGET_2_DNS',        'Target to DNS'),
    ('TARGET_2_IP',         'Target to IP address'),
    ('DNS_2_IP',            'DNS to IP address'),
    ('IP_2_DNS',            'IP address to DNS'),
    ('IP_2_DISCO_SERV',     'IP address to Discovered Services'),
    ('DISCO_SERV_2_CERT',   'Discovered Services to Certificate'),
    ('CERT_2_DNS',          'Certificate to DNS'),
    ('IP_2_ASN',            'IP address to Autonomous Number'),
    ('IP_2_GEO',            'IP address to GeoIP Location'),
    ('DISCO_SERV_2_HTTP',   'Discovered Services to HTTP'),
    ('HTTP_2_HTTP',         'HTTP to HTTP (redirect)')
]

class Transformation(models.Model):
    transformation_dt               = models.DateTimeField(auto_now=True,blank=True)

    transformation_status           = models.CharField(max_length=32, choices=TRANSFORMATION_STATUS)
    transformation_type             = models.CharField(max_length=32, choices=TRANSFORMATION_TYPES)

    transformation_from_target      = models.ForeignKey(to=ScanTarget,          related_name='transformation_from_target',      on_delete=models.CASCADE, null=True, blank=True)
    transformation_from_dns         = models.ForeignKey(to=DnsQuery,            related_name='transformation_from_dns',         on_delete=models.CASCADE, null=True, blank=True)
    transformation_from_ip          = models.ForeignKey(to=InternetAddress,     related_name='transformation_from_ip',          on_delete=models.CASCADE, null=True, blank=True)
    transformation_from_disco_serv  = models.ForeignKey(to=ServiceDiscovered,   related_name='transformation_from_disco_serv',  on_delete=models.CASCADE, null=True, blank=True)
    transformation_from_cert        = models.ForeignKey(to=Certificate,         related_name='transformation_from_cert',        on_delete=models.CASCADE, null=True, blank=True)
    transformation_from_asn         = models.ForeignKey(to=AutonomousSystem,    related_name='transformation_from_asn',         on_delete=models.CASCADE, null=True, blank=True)
    transformation_from_geo         = models.ForeignKey(to=IPGeoLocation,       related_name='transformation_from_geo',         on_delete=models.CASCADE, null=True, blank=True)
    transformation_from_http        = models.ForeignKey(to=HTTPRedirect,        related_name='transformation_from_http',        on_delete=models.CASCADE, null=True, blank=True)

    transformation_to_target        = models.ForeignKey(to=ScanTarget,          related_name='transformation_to_target',      on_delete=models.CASCADE, null=True, blank=True)
    transformation_to_dns           = models.ForeignKey(to=DnsQuery,            related_name='transformation_to_dns',         on_delete=models.CASCADE, null=True, blank=True)
    transformation_to_ip            = models.ForeignKey(to=InternetAddress,     related_name='transformation_to_ip',          on_delete=models.CASCADE, null=True, blank=True)
    transformation_to_disco_serv    = models.ForeignKey(to=ServiceDiscovered,   related_name='transformation_to_disco_serv',  on_delete=models.CASCADE, null=True, blank=True)
    transformation_to_cert          = models.ForeignKey(to=Certificate,         related_name='transformation_to_cert',        on_delete=models.CASCADE, null=True, blank=True)
    transformation_to_asn           = models.ForeignKey(to=AutonomousSystem,    related_name='transformation_to_asn',         on_delete=models.CASCADE, null=True, blank=True)
    transformation_to_geo           = models.ForeignKey(to=IPGeoLocation,       related_name='transformation_to_geo',         on_delete=models.CASCADE, null=True, blank=True)
    transformation_to_http          = models.ForeignKey(to=HTTPRedirect,        related_name='transformation_to_http',        on_delete=models.CASCADE, null=True, blank=True)


    def __str__(self):
        if   self.transformation_type == 'TARGET_2_DNS':
            return "From: %s To: %s" % (self.transformation_from_target,        self.transformation_to_dns)
        elif self.transformation_type == 'TARGET_2_IP':
            return "From: %s To: %s" % (self.transformation_from_target,        self.transformation_to_ip)
        elif self.transformation_type == 'DNS_2_IP':
            return "From: %s To: %s" % (self.transformation_from_dns,           self.transformation_to_ip)
        elif self.transformation_type == 'IP_2_DNS':
            return "From: %s To: %s" % (self.transformation_from_ip,            self.self.transformation_to_dns)
        elif self.transformation_type == 'IP_2_DISCO_SERV':
            return "From: %s To: %s" % (self.transformation_from_ip,            self.transformation_to_disco_serv)
        elif self.transformation_type == 'DISCO_SERV_2_CERT':
            return "From: %s To: %s" % (self.transformation_from_disco_serv,    self.transformation_to_cert)
        elif self.transformation_type == 'CERT_2_DNS':
            return "From: %s To: %s" % (self.transformation_from_cert,          self.transformation_to_dns)
        elif self.transformation_type == 'IP_2_ASN':
            return "From: %s To: %s" % (self.transformation_from_ip,            self.transformation_to_asn)
        elif self.transformation_type == 'IP_2_GEO':
            return "From: %s To: %s" % (self.transformation_from_ip,            self.transformation_to_geo)
        elif self.transformation_type == 'DISCO_SERV_2_HTTP':
            return "From: %s To: %s" % (self.transformation_from_disco_serv,    self.transformation_to_http)
        elif self.transformation_type == 'HTTP_2_HTTP':
            return "From: %s To: %s" % (self.transformation_from_http,          self.transformation_to_http)
        else:
            for item in TRANSFORMATION_TYPES:
                if item[0] == self.transformation_type:
                    t_type = item[1]
                    break
            return "Unsupported transformation: %s" % t_type
