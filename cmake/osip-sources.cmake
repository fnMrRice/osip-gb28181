set(osip_parser_sources
    osip_proxy_authorization.c osip_auth_param.c osip_cseq.c osip_record_route.c
    osip_route.c osip_to.c osip_from.c osip_uri.c osip_authorization.c
    osip_header.c osip_www_authenticate.c osip_via.c osip_body.c osip_md5c.c
    osip_message.c osip_list.c osip_call_id.c osip_message_parse.c osip_contact.c
    osip_message_to_str.c osip_content_length.c osip_parser_cfg.c
    osip_content_type.c osip_proxy_authenticate.c osip_mime_version.c
    osip_port.c osip_call_info.c osip_content_disposition.c)
if(NOT OSIP_MINISIZE)
    list(APPEND osip_parser_sources
        osip_accept_encoding.c osip_content_encoding.c osip_authentication_info.c
        osip_proxy_authentication_info.c osip_accept_language.c osip_accept.c
        osip_alert_info.c osip_error_info.c osip_allow.c sdp_accessor.c sdp_message.c)
endif()
list(TRANSFORM osip_parser_sources PREPEND "src/osipparser2/")

set(osip_transaction_sources
    ict_fsm.c ist_fsm.c nict_fsm.c nist_fsm.c ict.c ist.c nict.c nist.c
    fsm_misc.c osip.c osip_transaction.c osip_event.c port_fifo.c
    osip_dialog.c osip_time.c)
if(NOT OSIP_MONOTHREAD)
    list(APPEND osip_transaction_sources port_sema.c port_thread.c port_condv.c)
endif()
list(TRANSFORM osip_transaction_sources PREPEND "src/osip2/")
