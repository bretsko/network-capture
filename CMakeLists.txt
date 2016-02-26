project(tcpdump_bretsko)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)

add_compile_options(-std=c11 -Wall)
add_definitions(-D_DEFAULT_SOURCE)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} -lpcap)
