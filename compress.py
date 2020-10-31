import os
from proc.pcap import Pcap
import sys
from multiprocessing.pool import Pool as ThreadPool
import csv


def run_compare(file_name):
    pcap = Pcap()
    packets = pcap.parse(file_name)
    out_file_name = "{}.ns".format(file_name)
    with open(out_file_name, "w+") as output:
        for packet in packets:
            info = packet.raw_data.hex() + '\n'
            output.write(info)

    val = os.popen("./ns_compress {}".format(file_name))
    result = val.read()
    result = result.split("\n")
    result = [value.split(":")[1][1:] for value in result[:-1]]
    result = [os.path.split(file_name)[-1]] + result
    os.remove(out_file_name)
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("There should be one and only one directory name in the given args.")
    path = os.path.abspath(sys.argv[1])
    file_names = os.listdir(path)
    files = []
    for file_name in file_names:
        if file_name.endswith(".pcap"):
            files.append(os.path.join(path, file_name))
    pool = ThreadPool(12)
    results = pool.map(run_compare, files)
    pool.close()
    pool.join()

    with open("result.csv", 'w+') as out:
        csv_writer = csv.writer(out)
        csv_writer.writerow(["file", "ns_gzip c_ratio", "ns_gzip c_t", "ns_zstd c_ratio", "ns_zstd c_t", "gzip c_ratio", "gzip c_t", "zstd c_ratio", "zstd c_t"])
        csv_writer.writerows(results)
