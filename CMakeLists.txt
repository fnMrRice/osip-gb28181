cmake_minimum_required(VERSION 3.21)
project(osip2 VERSION 5.3.2 DESCRIPTION "GNU oSIP parser and transaction engine" LANGUAGES C)

include(GNUInstallDirs)
option(BUILD_SHARED_LIBS "Build shared oSIP libraries" OFF)
option(OSIP_MONOTHREAD "Build without the oSIP thread abstraction layer" OFF)
option(OSIP_MINISIZE "Omit optional SIP headers and SDP support" OFF)
option(OSIP_ENABLE_TRACE "Enable oSIP trace messages" ON)
option(OSIP_BUILD_TESTS "Build the upstream parser test programs" OFF)
option(OSIP_INSTALL "Generate oSIP installation and package targets" ON)

include("${CMAKE_CURRENT_LIST_DIR}/cmake/osip-platform.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/cmake/osip-sources.cmake")

add_library(osipparser2 ${osip_parser_sources})
add_library(osip2 ${osip_transaction_sources})
add_library(osip2::osipparser2 ALIAS osipparser2)
add_library(osip2::osip2 ALIAS osip2)
target_link_libraries(osip2 PUBLIC osipparser2)

foreach(osip_target IN ITEMS osipparser2 osip2)
    set_target_properties(${osip_target} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        VERSION 15.0.1
        SOVERSION 15
        WINDOWS_EXPORT_ALL_SYMBOLS YES
        POSITION_INDEPENDENT_CODE YES)
    target_include_directories(${osip_target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_compile_definitions(${osip_target} PRIVATE HAVE_CONFIG_H)
    if(OSIP_MONOTHREAD)
        target_compile_definitions(${osip_target} PUBLIC OSIP_MONOTHREAD)
    endif()
    if(OSIP_MINISIZE)
        target_compile_definitions(${osip_target} PUBLIC MINISIZE)
    endif()
    if(OSIP_ENABLE_TRACE)
        target_compile_definitions(${osip_target} PUBLIC ENABLE_TRACE)
    endif()
    if(WIN32)
        target_compile_definitions(${osip_target} PUBLIC WIN32)
        target_compile_definitions(${osip_target} PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
    endif()
endforeach()

if(WIN32)
    target_link_libraries(osipparser2 PRIVATE advapi32)
endif()
if(OSIP_NEEDS_THREADS)
    target_link_libraries(osip2 PUBLIC Threads::Threads)
endif()
if(OSIP_CLOCK_LIBRARY)
    target_link_libraries(osip2 PRIVATE "${OSIP_CLOCK_LIBRARY}")
endif()

if(OSIP_BUILD_TESTS)
    enable_testing()
    include("${CMAKE_CURRENT_LIST_DIR}/cmake/osip-tests.cmake")
endif()
if(OSIP_INSTALL)
    include("${CMAKE_CURRENT_LIST_DIR}/cmake/osip-install.cmake")
endif()
