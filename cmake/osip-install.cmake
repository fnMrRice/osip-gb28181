include(CMakePackageConfigHelpers)

set(osip_package_directory "${CMAKE_INSTALL_LIBDIR}/cmake/osip2")
install(TARGETS osipparser2 osip2 EXPORT osip2Targets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(DIRECTORY include/osip2 include/osipparser2
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.h" PATTERN "internal.h" EXCLUDE)
install(EXPORT osip2Targets NAMESPACE osip2:: DESTINATION "${osip_package_directory}")
configure_package_config_file("${CMAKE_CURRENT_LIST_DIR}/osip2Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/osip2Config.cmake"
    INSTALL_DESTINATION "${osip_package_directory}")
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/osip2ConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}" COMPATIBILITY SameMajorVersion)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/osip2Config.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/osip2ConfigVersion.cmake"
    DESTINATION "${osip_package_directory}")

set(OSIP_PC_CFLAGS "")
if(OSIP_MONOTHREAD)
    string(APPEND OSIP_PC_CFLAGS " -DOSIP_MONOTHREAD")
endif()
if(OSIP_MINISIZE)
    string(APPEND OSIP_PC_CFLAGS " -DMINISIZE")
endif()
if(OSIP_ENABLE_TRACE)
    string(APPEND OSIP_PC_CFLAGS " -DENABLE_TRACE")
endif()
set(OSIP_PC_LIBS_PRIVATE "${CMAKE_THREAD_LIBS_INIT}")
if(WIN32)
    string(APPEND OSIP_PC_CFLAGS " -DWIN32")
    string(APPEND OSIP_PC_LIBS_PRIVATE " -ladvapi32")
endif()
if(OSIP_CLOCK_LIBRARY)
    string(APPEND OSIP_PC_LIBS_PRIVATE " -l${OSIP_CLOCK_LIBRARY}")
endif()
file(RELATIVE_PATH OSIP_PC_PREFIX "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig"
     "${CMAKE_INSTALL_PREFIX}")
configure_file("${CMAKE_CURRENT_LIST_DIR}/libosip2.pc.in"
               "${CMAKE_CURRENT_BINARY_DIR}/libosip2.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libosip2.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
install(FILES COPYING DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/osip2")
