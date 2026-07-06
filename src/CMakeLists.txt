add_library(hollowdet_core STATIC
  core/memscan.cpp
  core/peparse.cpp
  core/config.cpp
  core/evidence.cpp
  core/json.cpp
  core/util.cpp
)
target_include_directories(hollowdet_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(hollowdet_core PUBLIC Psapi Shlwapi Advapi32)

add_executable(hollowdet cli/main.cpp)
target_link_libraries(hollowdet PRIVATE hollowdet_core Psapi Shlwapi Advapi32)

install(TARGETS hollowdet RUNTIME DESTINATION bin)
