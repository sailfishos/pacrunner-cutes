find_package(Qt5Core REQUIRED)
set(CMAKE_AUTOMOC TRUE)

configure_file(config.hpp.in config.hpp @ONLY)

add_library(pacrunner-cutes MODULE
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
