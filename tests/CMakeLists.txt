add_executable(hollow_tests test_runner.cpp)
target_link_libraries(hollow_tests PRIVATE hollowdet_core)

add_test(NAME selfcheck COMMAND $<TARGET_FILE:hollowdet> self-check)
add_test(NAME scan_target COMMAND $<TARGET_FILE:hollow_tests> $<TARGET_FILE:target_anom>)
