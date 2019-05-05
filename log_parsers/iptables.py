import re
from dateutil.parser import parse


class IpTables(object):
    def __init__(self):
        self.data = []
        self.compile_regex()

    def compile_regex(self):
        rex = {
            "meta": r"(?P<date>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) (?P<hostname>\w+) (?P<daemon_name>[\w\[\]\d]+):",
            "rule": r": FW (?P<rule>[^:]+):",
            "inn": r"IN=(?P<inn>[^ ]+) ",
            "out": r"OUT=(?P<out>[^ ]+) ",
            "mac": r"MAC=(?P<mac>[^ ]+) ",
            "src": r"SRC=(?P<src>[^ ]+) ",
            "dst": r"DST=(?P<dst>[^ ]+) ",
            "tos": r"TOS=(?P<tos>[^ ]+) ",
            "prec": r"PREC=(?P<prec>[^ ]+) ",
            "ttl": r"TTL=(?P<ttl>[^ ]+) ",
            "id": r"ID=(?P<id>[^ ]+) ",
            "proto": r"PROTO=(?P<proto>[^ ]+) ",
            "spt": r"SPT=(?P<spt>[^ ]+) ",
            "dpt": r"DPT=(?P<dpt>[^ ]+) ",
        }
        for field, regex in rex.items():
            self.__dict__[field] = re.compile(regex)

    def read(self, f):
        for line in f.readlines():
            fields = self.procecess(line)
            if not fields:
                continue
            self.data.append(fields)

    def procecess(self, line):
        fields = {}
        if ": FW" not in line:
            return fields
        fields.update(self.metadata(line))
        fields.update(self.ipt_log(line))
        return fields

    def metadata(self, line):
        meta = re.match(self.meta, line).groupdict()
        meta["date"] = parse(meta["date"])
        return meta

    def ipt_log(self, line):
        return {
            "rule": re.search(self.rule, line)[1],
            "in": re.search(self.inn, line)[1],
            "out": re.search(self.out, line)[1],
            "mac": re.search(self.mac, line)[1],
            "src": re.search(self.src, line)[1],
            "dst": re.search(self.dst, line)[1],
            "tos": re.search(self.tos, line)[1],
            "prec": re.search(self.prec, line)[1],
            "ttl": re.search(self.ttl, line)[1],
            "id": re.search(self.id, line)[1],
            "proto": re.search(self.proto, line)[1],
            "spt": re.search(self.spt, line)[1],
            "dpt": re.search(self.dpt, line)[1],
        }
