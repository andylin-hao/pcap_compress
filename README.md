Comparisons of multiple compression techniques' effects on pcap files, including:
* gzip (level 6)
* zstandard (level 22)
* netsight (basically a combination of Van Jacobson Header Compression and gzip, refer to https://www.usenix.org/system/files/conference/nsdi14/nsdi14-paper-handigol.pdf)
* netsight replacing gzip with zstandard

For pcap analysis, refer to https://github.com/mengdj/python.
For pcap file acquisition, refer to https://www.netresec.com/?page=PcapFiles.

To run tests on multiple pcap files, just type ``python3 compress.py ${path_include_pcap_files}``. The program will automatically detect pcap files under the given path and generate a ``csv`` file as result. 
