set(osip_test_tools
    turl:turls:urls tfrom:tfrom:froms tto:tto:tos tcontact:tcontact:contacts
    tvia:tvia:vias tcallid:tcallid:callids tcontentt:tcontentt:contenttypes
    trecordr:trecordr:recordroutes troute:troute:routes twwwa:twwwa:wwwas)
foreach(osip_test_tool IN LISTS osip_test_tools)
    string(REPLACE ":" ";" osip_test_parts "${osip_test_tool}")
    list(GET osip_test_parts 0 osip_test_target)
    list(GET osip_test_parts 1 osip_test_source)
    list(GET osip_test_parts 2 osip_test_data)
    add_executable(${osip_test_target} "src/test/${osip_test_source}.c")
    target_link_libraries(${osip_test_target} PRIVATE osipparser2)
    target_include_directories(${osip_test_target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_compile_definitions(${osip_test_target} PRIVATE HAVE_CONFIG_H)
    add_test(NAME "osip.${osip_test_target}" COMMAND "${CMAKE_COMMAND}"
        "-DOSIP_TEST_PROGRAM=$<TARGET_FILE:${osip_test_target}>"
        "-DOSIP_TEST_DATA=${CMAKE_CURRENT_SOURCE_DIR}/src/test/res/${osip_test_data}.txt"
        -P "${CMAKE_CURRENT_LIST_DIR}/osip-header-smoke.cmake")
    set_tests_properties("osip.${osip_test_target}" PROPERTIES LABELS smoke)
    set_target_properties(${osip_test_target} PROPERTIES FOLDER test)
endforeach()

if(NOT OSIP_MINISIZE)
    add_executable(torture_test src/test/torture.c)
    target_link_libraries(torture_test PRIVATE osipparser2)
    target_include_directories(torture_test PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_compile_definitions(torture_test PRIVATE HAVE_CONFIG_H)
    set_target_properties(torture_test PROPERTIES FOLDER test)
    file(GLOB osip_torture_data CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/test/res/sip[0-9]*"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/test/res/sip-malformed[0-9]*")
    # These legacy fixtures expect acceptance, but the fork deliberately rejects
    # invalid or mismatched Content-Length values rather than inferring a body.
    set(osip_strict_content_length_cases
        sip-malformed21 sip-malformed5 sip0 sip17 sip2 sip42 sip44 sip63
        sip66 sip68 sip81 sip91)
    # Bare CR header framing and control bytes in an authentication scheme.
    set(osip_strict_syntax_cases sip88 sip94)
    foreach(osip_fixture IN LISTS osip_torture_data)
        get_filename_component(osip_fixture_name "${osip_fixture}" NAME)
        if(osip_fixture_name MATCHES "^sip(-malformed)?[0-9]+$")
            set(osip_fixture_arguments "")
            if(osip_fixture_name IN_LIST osip_strict_content_length_cases OR
               osip_fixture_name IN_LIST osip_strict_syntax_cases)
                list(APPEND osip_fixture_arguments -e -5)
            endif()
            add_test(NAME "osip.${osip_fixture_name}" COMMAND torture_test
                "${osip_fixture}" -c ${osip_fixture_arguments})
            set_tests_properties("osip.${osip_fixture_name}" PROPERTIES
                FAIL_REGULAR_EXPRESSION "============================ FAILED")
        endif()
    endforeach()
endif()
