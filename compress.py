import gzip
import zstandard as zstd
import os
from proc.pcap import Pcap
import time
import sys


def cpz_gzip(file_name):
    with open(file_name, 'rb') as input:
        data = input.read()
        start = time.time()
        cpz_data = gzip.compress(data, compresslevel=6)
        elapse = time.time() - start

    print('gzip compression rate: {}%'.format((len(data) - len(cpz_data)) / len(data) * 100))
    print('gzip time consumption: {} μs'.format(elapse * 1000000))


def cpz_zstd(file_name):
    cctx = zstd.ZstdCompressor(level=22)
    with open(file_name, 'rb') as input:
        data = input.read()
        start = time.time()
        cpz_data = cctx.compress(input.read())
        elapse = time.time() - start

    print('zstandard compression rate: {}%'.format((len(data) - len(cpz_data)) / len(data) * 100))
    print('zstandard time consumption: {} μs'.format(elapse * 1000000))


def cpz_ns(file_name):
    pcap = Pcap()
    packets = pcap.parse(file_name)
    data = ''
    for idx, packet in enumerate(packets):
        str = packet.raw_data.hex()
        data += str + "\n"
    out_file_name = "{}.ns".format(file_name)
    with open(out_file_name, "w+") as output:
        output.write(data)

    out_file_name = os.path.join(os.getcwd(), out_file_name)
    val = os.popen("./ns_compress {}".format(out_file_name))
    print(val.read())


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("There should be one and only one file name in the given args.")
    file_name = sys.argv[1]
    cpz_gzip(file_name)
    cpz_zstd(file_name)
    cpz_ns(file_name)
