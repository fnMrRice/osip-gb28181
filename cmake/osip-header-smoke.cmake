# The upstream header tools return zero even when their input cannot be read.
# Their corpus mixes valid and invalid headers, so these remain smoke checks.
execute_process(COMMAND "${OSIP_TEST_PROGRAM}" "${OSIP_TEST_DATA}"
    RESULT_VARIABLE osip_smoke_result
    OUTPUT_VARIABLE osip_smoke_output
    ERROR_VARIABLE osip_smoke_error)
if(NOT osip_smoke_result STREQUAL "0" OR
   osip_smoke_output MATCHES "Failed to open" OR
   NOT osip_smoke_output MATCHES "result:")
    message(FATAL_ERROR "Header smoke check failed (${osip_smoke_result}):\n${osip_smoke_output}\n${osip_smoke_error}")
endif()
