import re
import json


class NmapScanParser:

    def __init__(self, input_file: str, output_file: str):
        self.input = input_file
        self.output = output_file
        self.result = []

    @staticmethod
    def get_services(block: str, stop_word: str):
        """
        :param block:
            Nmap scan report for 8.8.8.8
            Not shown: 999 closed ports
            PORT     STATE SERVICE
            8081/tcp open  blackice-icecap
        :param stop_word: A word after which list of services beginning
        :return: ['8081/tcp open  blackice-icecap', ...]
        """
        padding = block.index(stop_word)
        return block[padding + len(stop_word) + 1:].split('\n')

    @staticmethod
    def parse_services_to_json(services: list):
        """
        :param services: ['80/tcp   open  http', '22/tcp   open  ssh', ... ]
        :return: [{'port': '80/tcp', 'state': 'open', 'protocol': 'http'}, ...]
        """
        result = []
        for service in services:
            service_meta = service.split()

            if not service_meta:
                continue

            result.append({
                'port': service_meta[0],
                'state': service_meta[1],
                'protocol': service_meta[2]
            })

        return result

    @staticmethod
    def get_block_meta(block):
        ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', block)
        hostname = re.findall(r'for (\S+) \(', block)
        return {'ip': ip[0] if ip else None,
                'hostname': hostname[0] if hostname else None}

    def parse(self):
        """
        :param input_file

            Nmap scan report for 8.8.8.8
            Not shown: 999 closed ports
            PORT     STATE SERVICE
            8081/tcp open  blackice-icecap

            Nmap scan report for 8.8.8.8
            Not shown: 999 closed ports
            PORT     STATE SERVICE
            8181/tcp open  intermapper

            ...
        """
        with open('local_network_scan', 'r') as file:
            scan_content = file.read()

        splitted = scan_content.split('\n\n')

        for block in splitted:
            meta = self.get_block_meta(block)

            if not meta['ip']:
                continue

            services = self.get_services(block, 'SERVICE')
            services_json = self.parse_services_to_json(services)

            self.result.append({**meta, 'services': services_json})

    def write_result_to_json(self):
        with open(self.output, 'w') as file:
            json.dump(self.result, file)


parser = NmapScanParser('local_network_scan', 'formatted_scan.json')
parser.parse()
parser.write_result_to_json()