import collections
import os.path
import re
import sys
import zlib

from scapy.layers.inet import TCP
from scapy.utils import rdpcap

OUT_DIR = '/security/scapy/resources/out'
IN_DIR = '/security/scapy/resources/in'
PCAPS = '/home/shashank/PycharmProjects/pythonProject/security/resources/pcaps'

Response = collections.namedtuple('Response', ['header', 'payload'])


def get_header(payload):
    try:
        header_raw = payload[:payload.index(b'\r\n\r\n') + 2]
    except ValueError:
        sys.stdout.write('_')
        sys.stdout.flush()
        return None
    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode()))
    if 'Content-Type' not in header:
        return None
    return header


def extract_content(response, content_name='image'):
    content, content_type = None, None
    print(response.header['Content-Type'])
    if content_name in response.header['Content-Type']:
        content_type = response.header['Content-Type'].split('/')[1]
        content = response.payload[response.payload.index(b'\r\n\r\n') + 4:]
        if 'Content_Encoding' in response.header:
            if response.header['Content-Encoding'] == 'gzip':
                content = zlib.decompress(response.payload, zlib.MAX_WBITS | 32)
            if response.header['Content-Encoding'] == 'deflate':
                content = zlib.decompress(response.payload)
    return content, content_type


class Recapper:
    def __init__(self, fname):
        pcap = rdpcap(fname)
        self.sessions = pcap.sessions()
        self.responses = list()

    def get_responses(self):
        for session in self.sessions:
            payload = b''
            for packet in self.sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        payload += bytes(packet[TCP].payload)
                except IndexError:
                    sys.stdout.write('x')
                    sys.stdout.flush()
            if payload:
                header = get_header(payload)
                if header is None:
                    continue
                self.responses.append(Response(header=header, payload=payload))

    def write(self, content_name):
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response, content_name)
            if content and content_type:
                fname = os.path.join(OUT_DIR, f'ex_{i}.{content_type}')
                print(f'writing {fname}')
                open(fname, 'wb').write(content)


if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'arper-new-new.pcap')
    recapper = Recapper(pfile)
    recapper.get_responses()
    recapper.write('image')
