import re


class IscDhcpServer(object):
    def __init__(self, log_file):
        self.data = []
        self.log_file = log_file
        self.compile_regex()

    def compile_regex(self):
        rex = {
            "meta": r"(?P<date>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) (?P<hostname>\w+) (?P<daemon_name>\w+):",
            "ip": r"(?P<ip>(\d+\.*){4})",
            "hw": r"(?P<hw>([\w\d]{2}:*){6})",
            "name": r"(?P<name>\([\w\d-]+\))",
            "via": r"via (?P<via>([\w\d-]+|(\d+\.*){4}))",
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
        fields.update(self.metadata(line))
        if "DHCPACK" in line:
            fields.update(self.dhcp_ack(line))
        elif "DCHPINFORM" in line:
            fields.update(self.dhcp_inform(line))
        elif "DCHPNAK" in line:
            fields.update(self.dhcp_nak(line))
        elif "DCHPREQUEST" in line:
            fields.update(self.dhcp_request(line))
        return fields

    def metadata(self, line):
        return re.match(self.meta, line).groupdict()

    def dhcp_ack(self, line):
        ip_m = re.search(self.ip, line)
        hw_m = re.search(self.hw, line)
        name_m = re.search(self.name, line)
        via_m = re.search(self.via, line)
        return {
            "message_type": "DHCPACK",
            "ip": ip_m["ip"],
            "hw": hw_m["hw"],
            "name": name_m["name"] if name_m else None,
            "via": via_m["via"] if via_m else None,
        }

    def dhcp_inform(self, line):
        return {}

    def dhcp_nak(self, line):
        return {}

    def dhcp_request(self, line):
        return {}
