enable_testing()
add_executable(hollow_tests tests/test_runner.cpp)
target_link_libraries(hollow_tests PRIVATE hollowdet_core)

add_test(NAME selfcheck COMMAND hollowdet self-check)
add_test(NAME scan_target COMMAND hollow_tests)
