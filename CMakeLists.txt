cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

project(amz)

set(GENERIC_LIB_VERSION "1.0.0")
set(GENERIC_LIB_SOVERSION "1")

# all sources
set(SOURCES
    src/amz.cpp
)

set(HEADERS
    src/amz.h
)

find_package(OpenSSL REQUIRED)

# some other includes
include_directories(${CMAKE_BINARY_DIR})

# create the executables
add_library(amz SHARED ${SOURCES})

# link them to one file
target_link_libraries(amz ${OPENSSL_LIBRARIES})

set_target_properties(amz PROPERTIES VERSION ${GENERIC_LIB_VERSION} SOVERSION
    ${GENERIC_LIB_SOVERSION})

# install the program
install(TARGETS amz LIBRARY DESTINATION lib)

install(FILES ${HEADERS} DESTINATION include)
