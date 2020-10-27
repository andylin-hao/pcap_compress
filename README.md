Comparisons of multiple compression techniques' effects on pcap files, including:
* gzip (level 6)
* zstandard (level 22)
* netsight (basically a combination of Van Jacobson Header Compression and gzip, refer to https://www.usenix.org/system/files/conference/nsdi14/nsdi14-paper-handigol.pdf)

For pcap analysis, refer to https://github.com/mengdj/python.
For pcap file acquisition, refer to https://www.netresec.com/?page=PcapFiles.
Here are some basic results when runned on a 500 MB pcap file (https://github.com/nccgroup/Cyber-Defence/blob/master/Intelligence/Honeypot-Data/2020-F5-and-Citrix/f5-honeypot-release.tar.gz):
* gzip: compress rate is 83.25%, taking 8694523 μs
* zstandard: compress rate is 99.999998%, taking 16 μs (outstanding!)
* netsight: compress rate is 97.85%, taking 495 μs

To run tests on any pcap files, just type ``python3 compress.py ${pcap_file_path}``. You might also want to first install the prerequisites specified in ``requirements.txt``.
