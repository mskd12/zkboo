cmake_minimum_required(VERSION 3.13)
project(zkboo C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-Wall -Werror -Wno-error=unused-variable -Wno-error=unused-but-set-variable -fopenmp")

link_directories(/usr/local/lib)

add_executable(prover prover.c)
target_link_libraries(prover
        -g -lssl -lcrypto)

add_executable(verifier verifier.c)
target_link_libraries(verifier
        -g -lssl -lcrypto)
