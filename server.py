import random
import socket
import sqlite3
import struct
import sys
import time

ROOT_SERVER_IPS = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]

DEFAULT_PORT = 53
HEADER_LENGTH = 12
NORMAL_REPLY_LIMIT = 512
EDNS_REPLY_LIMIT = 4096
SECONDS_TO_WAIT = 2.0
MAX_STEPS = 16
MAX_NESTED_LOOKUPS = 3
SERVERS_TO_TRY = 3

A_RECORD = 1
NS_RECORD = 2
CNAME_RECORD = 5
SOA_RECORD = 6
PTR_RECORD = 12
MX_RECORD = 15
OPT_RECORD = 41
ANY_RECORD = 255
INTERNET_CLASS = 1

NO_ERROR = 0
SERVER_FAILURE = 2
NAME_NOT_FOUND = 3

RESPONSE_BIT = 0x8000
TRUNCATED_BIT = 0x0200
RECURSION_DESIRED_BIT = 0x0100
RECURSION_AVAILABLE_BIT = 0x0080
OPCODE_BITS = 0x7800
ERROR_CODE_BITS = 0x000F

class FormatError(Exception):
    pass

class Record:
    def __init__(self, owner, rtype, rclass, ttl, data):
        self.owner = owner
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.data = data

class Packet:
    def __init__(self):
        self.id = 0
        self.flags = 0
        self.question = None
        self.answers = []
        self.authority = []
        self.additional = []
        self.udp_size = None

def unpack_name(packet, pos):
    labels = []
    wire_length = 1
    resume = -1
    while True:
        if pos >= len(packet):
            raise FormatError("name runs past end of message")
        size = packet[pos]
        if size == 0:
            pos += 1
            break
        if size >= 192:
            if pos + 1 >= len(packet):
                raise FormatError("truncated compression pointer")
            jump = (size - 192) * 256 + packet[pos + 1]
            if jump >= pos:
                raise FormatError("bad compression pointer")
            if resume == -1:
                resume = pos + 2
            pos = jump
            continue
        if size > 63:
            raise FormatError("label longer than 63 octets")
        if pos + 1 + size > len(packet):
            raise FormatError("label runs past end of message")
        wire_length += size + 1
        if wire_length > 255:
            raise FormatError("name longer than 255 octets")
        labels.append(packet[pos + 1:pos + 1 + size].decode("latin-1"))
        pos += size + 1
    if resume == -1:
        resume = pos
    return ".".join(labels), resume

def pack_name(name):
    wire = b""
    if name != "":
        for label in name.split("."):
            wire += bytes([len(label)]) + label.encode("latin-1")
    return wire + b"\x00"

def decompress_rdata(packet, pos, size, rtype):
    stop = pos + size
    if rtype == NS_RECORD or rtype == CNAME_RECORD or rtype == PTR_RECORD:
        host, pos = unpack_name(packet, pos)
        return pack_name(host)
    if rtype == MX_RECORD:
        priority = packet[pos:pos + 2]
        host, pos = unpack_name(packet, pos + 2)
        return priority + pack_name(host)
    if rtype == SOA_RECORD:
        primary, pos = unpack_name(packet, pos)
        mailbox, pos = unpack_name(packet, pos)
        return pack_name(primary) + pack_name(mailbox) + packet[pos:stop]
    return packet[pos:stop]

def unpack_message(packet):
    if len(packet) < HEADER_LENGTH:
        raise FormatError("message shorter than header")
    msg = Packet()
    msg.id, msg.flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", packet[:HEADER_LENGTH])
    if qdcount != 1:
        raise FormatError("expected exactly one question")
    qname, pos = unpack_name(packet, HEADER_LENGTH)
    if pos + 4 > len(packet):
        raise FormatError("truncated question")
    qtype, qclass = struct.unpack("!HH", packet[pos:pos + 4])
    pos += 4
    msg.question = (qname, qtype, qclass)
    for section, count in [(msg.answers, ancount), (msg.authority, nscount),
                           (msg.additional, arcount)]:
        for i in range(count):
            owner, pos = unpack_name(packet, pos)
            if pos + 10 > len(packet):
                raise FormatError("truncated record")
            rtype, rclass, ttl, size = struct.unpack("!HHIH", packet[pos:pos + 10])
            pos += 10
            if pos + size > len(packet):
                raise FormatError("record runs past end of message")
            if rtype == OPT_RECORD:
                msg.udp_size = rclass
            else:
                data = decompress_rdata(packet, pos, size, rtype)
                section.append(Record(owner.lower(), rtype, rclass, ttl, data))
            pos += size
    if pos != len(packet):
        raise FormatError("trailing octets")
    return msg

def pack_message(msg_id, flags, question, answers, authority, additional,
                 edns, size_limit):
    qname, qtype, qclass = question
    body = pack_name(qname) + struct.pack("!HH", qtype, qclass)
    counts = [len(answers), len(authority), len(additional)]
    records = b""
    for record in answers + authority + additional:
        records += pack_name(record.owner)
        records += struct.pack("!HHIH", record.rtype, record.rclass, record.ttl,
                               len(record.data))
        records += record.data
    opt = b""
    if edns:
        opt = b"\x00" + struct.pack("!HHIH", OPT_RECORD, EDNS_REPLY_LIMIT, 0, 0)
    if HEADER_LENGTH + len(body) + len(records) + len(opt) > size_limit:
        flags = flags | TRUNCATED_BIT
        records = b""
        counts = [0, 0, 0]
    if edns:
        counts[2] += 1
    header = struct.pack("!HHHHHH", msg_id, flags, 1, counts[0], counts[1], counts[2])
    return header + body + records + opt

def exchange(packet, ip, port=DEFAULT_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SECONDS_TO_WAIT)
    try:
        sock.connect((ip, port))
        sock.send(packet)
        return sock.recv(65535)
    except OSError:
        return b""
    finally:
        sock.close()

def name_in_rdata(record):
    host, pos = unpack_name(record.data, 0)
    return host.lower()

def ip_addresses(records):
    found = []
    for record in records:
        if record.rtype == A_RECORD and len(record.data) == 4:
            found.append(socket.inet_ntoa(record.data))
    return found

def is_under(name, zone):
    return zone == "" or name == zone or name.endswith("." + zone)

def parent_of(name):
    if "." in name:
        return name.split(".", 1)[1]
    return ""

class RecordCache:
    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute(
            "CREATE TABLE records (owner TEXT, rtype INTEGER, rclass INTEGER,"
            " data BLOB, expires REAL)")

    def remove(self, owner, rtype, rclass):
        self.db.execute(
            "DELETE FROM records WHERE owner = ? AND rtype = ? AND rclass = ?",
            (owner, rtype, rclass))

    def store(self, records):
        fetched = time.time()
        for record in records:
            self.remove(record.owner, record.rtype, record.rclass)
        for record in records:
            if record.ttl > 0:
                self.db.execute(
                    "INSERT INTO records VALUES (?, ?, ?, ?, ?)",
                    (record.owner, record.rtype, record.rclass, record.data,
                     fetched + record.ttl))

    def find(self, owner, rtype, rclass):
        now = time.time()
        rows = self.db.execute(
            "SELECT data, expires FROM records"
            " WHERE owner = ? AND rtype = ? AND rclass = ?",
            (owner, rtype, rclass)).fetchall()
        fresh = []
        for data, expires in rows:
            if expires <= now:
                self.remove(owner, rtype, rclass)
                return []
            fresh.append(Record(owner, rtype, rclass, int(expires - now), data))
        return fresh

class Resolver:
    def __init__(self, root_servers=ROOT_SERVER_IPS):
        self.root_servers = root_servers
        self.cache = RecordCache()

    def cached_ips(self, hosts):
        ips = []
        for host in hosts:
            ips = ips + ip_addresses(self.cache.find(host, A_RECORD, INTERNET_CLASS))
        return ips

    def nearest_zone(self, qname, qclass):
        zone = qname
        while zone != "":
            hosts = []
            for record in self.cache.find(zone, NS_RECORD, qclass):
                hosts.append(name_in_rdata(record))
            ips = self.cached_ips(hosts)
            if len(ips) > 0:
                return zone, ips
            zone = parent_of(zone)
        return "", self.root_servers

    def nameserver_ips(self, hosts, depth):
        ips = self.cached_ips(hosts)
        if len(ips) > 0 or depth >= MAX_NESTED_LOOKUPS:
            return ips
        for host in hosts[:SERVERS_TO_TRY]:
            rcode, answers, authority = self.lookup(host, A_RECORD, INTERNET_CLASS, depth + 1)
            ips = ip_addresses(answers)
            if len(ips) > 0:
                return ips
        return []

    def query_any(self, ips, qname, qtype, qclass):
        candidates = list(ips)
        random.shuffle(candidates)
        for ip in candidates[:SERVERS_TO_TRY]:
            msg_id = random.randint(0, 65535)
            request = pack_message(msg_id, 0, (qname, qtype, qclass), [], [], [],
                                   True, EDNS_REPLY_LIMIT)
            try:
                reply = unpack_message(exchange(request, ip))
            except FormatError:
                continue
            if reply.id != msg_id or not reply.flags & RESPONSE_BIT:
                continue
            echoed, echoed_type, echoed_class = reply.question
            if (echoed.lower(), echoed_type, echoed_class) != (qname, qtype, qclass):
                continue
            if reply.flags & ERROR_CODE_BITS in (NO_ERROR, NAME_NOT_FOUND):
                return reply
        return None

    def walk(self, qname, qtype, qclass, depth):
        zone, ips = self.nearest_zone(qname, qclass)
        for hop in range(MAX_STEPS):
            reply = self.query_any(ips, qname, qtype, qclass)
            if reply is None:
                return SERVER_FAILURE, [], []
            matches = []
            aliases = []
            for record in reply.answers:
                if record.owner != qname or record.rclass != qclass:
                    continue
                if record.rtype == qtype or qtype == ANY_RECORD:
                    matches.append(record)
                elif record.rtype == CNAME_RECORD:
                    aliases.append(record)
            if len(matches) == 0:
                matches = aliases
            if len(matches) > 0:
                self.cache.store(matches)
                return NO_ERROR, matches, []
            soa = []
            delegation = []
            for record in reply.authority:
                if record.rtype == SOA_RECORD:
                    soa.append(record)
                elif (record.rtype == NS_RECORD and is_under(qname, record.owner)
                        and len(record.owner) > len(zone)):
                    delegation.append(record)
            rcode = reply.flags & ERROR_CODE_BITS
            if rcode == NAME_NOT_FOUND or len(delegation) == 0:
                return rcode, [], soa
            zone = delegation[0].owner
            hosts = []
            for record in delegation:
                hosts.append(name_in_rdata(record))
            glue = []
            for record in reply.additional:
                if record.owner in hosts and record.rtype == A_RECORD:
                    glue.append(record)
            self.cache.store(delegation + glue)
            ips = self.nameserver_ips(hosts, depth)
        return SERVER_FAILURE, [], []

    def lookup(self, qname, qtype, qclass, depth=0):
        chain = []
        for hop in range(MAX_STEPS):
            found = self.cache.find(qname, qtype, qclass)
            if len(found) == 0:
                found = self.cache.find(qname, CNAME_RECORD, qclass)
            if len(found) == 0:
                rcode, found, authority = self.walk(qname, qtype, qclass, depth)
                if len(found) == 0:
                    return rcode, chain, authority
            chain = chain + found
            if found[0].rtype != CNAME_RECORD or qtype in (CNAME_RECORD, ANY_RECORD):
                return NO_ERROR, chain, []
            qname = name_in_rdata(found[0])
        return SERVER_FAILURE, [], []

def handle_request(packet, resolver):
    try:
        request = unpack_message(packet)
    except FormatError as problem:
        print("dropped invalid message:", problem)
        return None
    if request.flags & RESPONSE_BIT or request.flags & OPCODE_BITS:
        print("dropped message that is not a standard query")
        return None
    qname, qtype, qclass = request.question
    try:
        rcode, answers, authority = resolver.lookup(qname.lower(), qtype, qclass)
    except Exception as problem:
        print("failed to resolve", qname, problem)
        rcode, answers, authority = SERVER_FAILURE, [], []
    print(qname, "type", qtype, "rcode", rcode, "answers", len(answers))
    flags = RESPONSE_BIT | RECURSION_AVAILABLE_BIT | (request.flags & RECURSION_DESIRED_BIT) | rcode
    if request.udp_size is None:
        return pack_message(request.id, flags, request.question, answers,
                            authority, [], False, NORMAL_REPLY_LIMIT)
    return pack_message(request.id, flags, request.question, answers,
                        authority, [], True, max(NORMAL_REPLY_LIMIT, request.udp_size))

def run(sock, resolver):
    while True:
        packet, client = sock.recvfrom(65535)
        response = handle_request(packet, resolver)
        if response is not None:
            sock.sendto(response, client)

def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", port))
    print("listening on UDP port", port)
    run(sock, Resolver())

if __name__ == "__main__":
    main()
