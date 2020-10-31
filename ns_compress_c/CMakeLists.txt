cmake_minimum_required(VERSION 3.16)
project(ns_compress)

set(CMAKE_CXX_STANDARD 14)

LINK_LIBRARIES(-lm -lz -lpcap -lzstd)
add_executable(ns_compress main.cpp compress.cc util.cc decompress.cc flow.cc packet.cc helper.cc cpz_gzip.cpp cpz_gzip.h cpz_zstd.cpp cpz_zstd.h cpz_ns.cpp cpz_ns.h)
target_compile_options(ns_compress PUBLIC "-pthread")
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)
target_link_libraries(ns_compress PRIVATE Threads::Threads)