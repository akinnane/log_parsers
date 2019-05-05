import re
from dateutil.parser import parse


class Named(object):
    def __init__(self):
        self.data = []
        self.compile_regex()

    def compile_regex(self):
        rex = {
            "meta": r"(?P<date>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) (?P<hostname>\w+) (?P<daemon_name>[\w\[\]\d]+):",
            "client": r"client (?P<client>(\d+\.*){4})#",
            "query": r"query: (?P<query>[\w\d\.-]+)",
            "record_type": r" IN (?P<record_type>[^ ]+)",
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
        if "query:" not in line:
            return fields
        fields.update(self.metadata(line))
        fields.update(self.dns_query(line))
        return fields

    def metadata(self, line):
        meta = re.match(self.meta, line).groupdict()
        meta["date"] = parse(meta["date"])
        return meta

    def dns_query(self, line):
        return {
            "client": re.search(self.client, line)[1],
            "query": re.search(self.query, line)[1],
            "record_type": re.search(self.record_type, line)[1],
        }
