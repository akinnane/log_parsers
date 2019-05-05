import re


class IscDhcpServer(object):
    def __init__(self):
        self.data = []
        self.compile_regex()

    def compile_regex(self):
        rex = {
            "meta": r"(?P<date>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) (?P<hostname>\w+) (?P<daemon_name>\w+):",
            "message_type": r"(?P<message_type>DHCP[A-Z]+)",
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
        if ": DHCP" in line:
            fields.update(self.dhcp_message(line))
        return fields

    def metadata(self, line):
        return re.match(self.meta, line).groupdict()

    def dhcp_message(self, line):
        message_type_m = re.search(self.message_type, line)
        ip_m = re.search(self.ip, line)
        hw_m = re.search(self.hw, line)
        name_m = re.search(self.name, line)
        via_m = re.search(self.via, line)
        return {
            "message_type": message_type_m["message_type"],
            "ip": ip_m["ip"],
            "hw": hw_m["hw"] if hw_m else None,
            "name": name_m["name"] if name_m else None,
            "via": via_m["via"] if via_m else None,
        }
