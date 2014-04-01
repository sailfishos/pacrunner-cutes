find_package(Qt5Core REQUIRED)
set(CMAKE_AUTOMOC TRUE)

configure_file(config.hpp.in config.hpp @ONLY)

add_library(pacrunner-cutes SHARED
  pacrunner.cpp
)

qt5_use_modules(pacrunner-cutes Core Qml)

target_link_libraries(pacrunner-cutes
  ${COR_LIBRARIES}
  ${CUTES_LIBRARIES}
  ${PACRUNNER_LIBRARIES}
  ${GLIB_LIBRARIES}
  )

install(TARGETS pacrunner-cutes DESTINATION ${DST_LIB}/pacrunner/plugins)
install(FILES pacrunner.js DESTINATION ${PACRUNNER_DATA_PATH})

add_executable(test_pacrunner_cutes test_pacrunner_cutes.cpp)
target_link_libraries(test_pacrunner_cutes
  pacrunner-cutes
  ${TUT_LIBRARIES}
  )

set(TESTS_DIR /opt/tests/pacrunner-cutes)
install(
  TARGETS test_pacrunner_cutes
  DESTINATION ${TESTS_DIR}
)
configure_file(tests.xml.in tests.xml @ONLY)
install(
  FILES tests.xml
  DESTINATION ${TESTS_DIR}
)
