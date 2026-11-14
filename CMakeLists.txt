cmake_minimum_required(VERSION 3.21)
project(rtxdiasm_fatbin_parse LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Static library for parsing/extracting PTX from NVIDIA fatbin containers.
# Handles uncompressed, LZ4-compressed (0x2000), and ZSTD-compressed (0x8000) PTX members.

add_library(rtxdiasm_fatbin_parse STATIC
  src/fatbin_parse.c
  src/cubin_texref.c
)

target_include_directories(rtxdiasm_fatbin_parse
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# --- External: lz4 (v1.11.1 submodule) ---
set(LZ4_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LZ4_BUILD_LEGACY_LZ4C OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
if(NOT TARGET lz4_static AND NOT TARGET lz4 AND NOT TARGET LZ4::lz4_static)
  add_subdirectory(external/lz4/build/cmake ${CMAKE_BINARY_DIR}/external/lz4 EXCLUDE_FROM_ALL)
endif()
if(TARGET lz4_static)
  set(RTXDIASM_FATBIN_LZ4_TARGET lz4_static)
elseif(TARGET LZ4::lz4_static)
  set(RTXDIASM_FATBIN_LZ4_TARGET LZ4::lz4_static)
elseif(TARGET lz4)
  set(RTXDIASM_FATBIN_LZ4_TARGET lz4)
else()
  message(FATAL_ERROR "lz4 library target not found in external/lz4 submodule")
endif()

# --- External: zstd (v1.5.7 submodule) ---
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
if(NOT TARGET libzstd_static AND NOT TARGET libzstd_shared AND NOT TARGET zstd::libzstd_static)
  add_subdirectory(external/zstd/build/cmake ${CMAKE_BINARY_DIR}/external/zstd EXCLUDE_FROM_ALL)
endif()
if(TARGET libzstd_static)
  set(RTXDIASM_FATBIN_ZSTD_TARGET libzstd_static)
elseif(TARGET zstd::libzstd_static)
  set(RTXDIASM_FATBIN_ZSTD_TARGET zstd::libzstd_static)
elseif(TARGET libzstd_shared)
  set(RTXDIASM_FATBIN_ZSTD_TARGET libzstd_shared)
else()
  message(FATAL_ERROR "zstd library target not found in external/zstd submodule")
endif()

target_include_directories(rtxdiasm_fatbin_parse PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/external/lz4/lib
  ${CMAKE_CURRENT_SOURCE_DIR}/external/zstd/lib
)
target_link_libraries(rtxdiasm_fatbin_parse PUBLIC ${RTXDIASM_FATBIN_LZ4_TARGET} ${RTXDIASM_FATBIN_ZSTD_TARGET})

if(MSVC)
  target_compile_options(rtxdiasm_fatbin_parse PRIVATE /W3)
  target_compile_definitions(rtxdiasm_fatbin_parse PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(rtxdiasm_fatbin_parse PRIVATE -Wall -Wextra)
endif()
