cmake_minimum_required(VERSION 3.20)
project(HollowDetect LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
add_compile_options(/W4 /permissive- /EHsc)
if (DEFINED ENV{CI})
  add_compile_options(/WX)
endif()

add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(tests)

install(FILES schema/anomaly.schema.json DESTINATION share/hollowdetect)
