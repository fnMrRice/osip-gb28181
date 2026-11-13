/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001-2020 Aymeric MOIZARD amoizard@antisip.com

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <osipparser2/internal.h>

#include <osipparser2/osip_port.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include "parser.h"
#include "osip_auth_param.h"
static const __osip_auth_field_t auth_fields[] = {
  {"username", offsetof(osip_authorization_t, username)},
  {"realm", offsetof(osip_authorization_t, realm)},
  {"nonce", offsetof(osip_authorization_t, nonce)},
  {"uri", offsetof(osip_authorization_t, uri)},
  {"response", offsetof(osip_authorization_t, response)},
  {"digest", offsetof(osip_authorization_t, digest)},
  {"algorithm", offsetof(osip_authorization_t, algorithm)},
  {"cnonce", offsetof(osip_authorization_t, cnonce)},
  {"opaque", offsetof(osip_authorization_t, opaque)},
  {"qop", offsetof(osip_authorization_t, message_qop)},
  {"nc", offsetof(osip_authorization_t, nonce_count)},
  {"version", offsetof(osip_authorization_t, version)},
  {"targetname", offsetof(osip_authorization_t, targetname)},
  {"gssapi-data", offsetof(osip_authorization_t, gssapi_data)},
  {"crand", offsetof(osip_authorization_t, crand)},
  {"cnum", offsetof(osip_authorization_t, cnum)},
};
#define AUTH_FIELD_COUNT (sizeof(auth_fields) / sizeof(auth_fields[0]))


int osip_authorization_init(osip_authorization_t **dest) {
  *dest = (osip_authorization_t *) osip_malloc(sizeof(osip_authorization_t));

  if (*dest == NULL)
    return OSIP_NOMEM;

  memset(*dest, 0, sizeof(osip_authorization_t));
  osip_list_init(&(*dest)->auth_params);
  return OSIP_SUCCESS;
}

/* fills the www-authenticate header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int osip_message_set_authorization(osip_message_t *sip, const char *hvalue) {
  osip_authorization_t *authorization;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return OSIP_SUCCESS;

  if (sip == NULL)
    return OSIP_BADPARAMETER;

  i = osip_authorization_init(&authorization);

  if (i != 0)
    return i;

  i = osip_authorization_parse(authorization, hvalue);

  if (i != 0) {
    osip_authorization_free(authorization);
    return i;
  }

  sip->message_property = 2;
  i = osip_list_add(&sip->authorizations, authorization, -1);
  if (i < 0) { osip_authorization_free(authorization); return i; }
  return OSIP_SUCCESS;
}

/* fills the www-authenticate structure.           */
/* INPUT : char *hvalue | value of header.         */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
/* TODO:
   digest-challenge tken has no order preference??
   verify many situations (extra SP....)
*/
int osip_authorization_parse(osip_authorization_t *value, const char *text) {
  if (value == NULL) return OSIP_BADPARAMETER;
  return __osip_auth_parse(value, &value->auth_type, &value->auth_param, &value->auth_params,
                           auth_fields, AUTH_FIELD_COUNT, text);
}

#ifndef MINISIZE
/* returns the authorization header.   */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
int osip_message_get_authorization(const osip_message_t *sip, int pos, osip_authorization_t **dest) {
  osip_authorization_t *authorization;

  *dest = NULL;

  if (osip_list_size(&sip->authorizations) <= pos)
    return OSIP_UNDEFINED_ERROR; /* does not exist */

  authorization = (osip_authorization_t *) osip_list_get(&sip->authorizations, pos);
  *dest = authorization;
  return pos;
}
#endif

char *osip_authorization_get_auth_type(const osip_authorization_t *authorization) {
  return authorization->auth_type;
}

void osip_authorization_set_auth_type(osip_authorization_t *authorization, char *auth_type) {
  authorization->auth_type = (char *) auth_type;
}

char *osip_authorization_get_username(osip_authorization_t *authorization) {
  return authorization->username;
}

void osip_authorization_set_username(osip_authorization_t *authorization, char *username) {
  authorization->username = (char *) username;
}

char *osip_authorization_get_realm(osip_authorization_t *authorization) {
  return authorization->realm;
}

void osip_authorization_set_realm(osip_authorization_t *authorization, char *realm) {
  authorization->realm = (char *) realm;
}

char *osip_authorization_get_nonce(osip_authorization_t *authorization) {
  return authorization->nonce;
}

void osip_authorization_set_nonce(osip_authorization_t *authorization, char *nonce) {
  authorization->nonce = (char *) nonce;
}

char *osip_authorization_get_uri(osip_authorization_t *authorization) {
  return authorization->uri;
}

void osip_authorization_set_uri(osip_authorization_t *authorization, char *uri) {
  authorization->uri = (char *) uri;
}

char *osip_authorization_get_response(osip_authorization_t *authorization) {
  return authorization->response;
}

void osip_authorization_set_response(osip_authorization_t *authorization, char *response) {
  authorization->response = (char *) response;
}

char *osip_authorization_get_digest(osip_authorization_t *authorization) {
  return authorization->digest;
}

void osip_authorization_set_digest(osip_authorization_t *authorization, char *digest) {
  authorization->digest = (char *) digest;
}

char *osip_authorization_get_algorithm(osip_authorization_t *authorization) {
  return authorization->algorithm;
}

void osip_authorization_set_algorithm(osip_authorization_t *authorization, char *algorithm) {
  authorization->algorithm = (char *) algorithm;
}

char *osip_authorization_get_cnonce(osip_authorization_t *authorization) {
  return authorization->cnonce;
}

void osip_authorization_set_cnonce(osip_authorization_t *authorization, char *cnonce) {
  authorization->cnonce = (char *) cnonce;
}

char *osip_authorization_get_opaque(osip_authorization_t *authorization) {
  return authorization->opaque;
}

void osip_authorization_set_opaque(osip_authorization_t *authorization, char *opaque) {
  authorization->opaque = (char *) opaque;
}

char *osip_authorization_get_message_qop(osip_authorization_t *authorization) {
  return authorization->message_qop;
}

void osip_authorization_set_message_qop(osip_authorization_t *authorization, char *message_qop) {
  authorization->message_qop = (char *) message_qop;
}

char *osip_authorization_get_nonce_count(osip_authorization_t *authorization) {
  return authorization->nonce_count;
}

void osip_authorization_set_nonce_count(osip_authorization_t *authorization, char *nonce_count) {
  authorization->nonce_count = (char *) nonce_count;
}

char *osip_authorization_get_version(osip_authorization_t *authorization) {
  return authorization->version;
}

void osip_authorization_set_version(osip_authorization_t *authorization, char *version) {
  authorization->version = (char *) version;
}

char *osip_authorization_get_targetname(osip_authorization_t *authorization) {
  return authorization->targetname;
}

void osip_authorization_set_targetname(osip_authorization_t *authorization, char *targetname) {
  authorization->targetname = (char *) targetname;
}

char *osip_authorization_get_gssapi_data(osip_authorization_t *authorization) {
  return authorization->gssapi_data;
}

void osip_authorization_set_gssapi_data(osip_authorization_t *authorization, char *gssapi_data) {
  authorization->gssapi_data = (char *) gssapi_data;
}

char *osip_authorization_get_crand(osip_authorization_t *authorization) {
  return authorization->crand;
}

void osip_authorization_set_crand(osip_authorization_t *authorization, char *crand) {
  authorization->crand = (char *) crand;
}

char *osip_authorization_get_cnum(osip_authorization_t *authorization) {
  return authorization->cnum;
}

void osip_authorization_set_cnum(osip_authorization_t *authorization, char *cnum) {
  authorization->cnum = (char *) cnum;
}

/* returns the authorization header as a string.          */
/* INPUT : osip_authorization_t *authorization | authorization header.  */
/* returns null on error. */
int osip_authorization_to_str(const osip_authorization_t *value, char **dest) {
  if (value == NULL || dest == NULL) return OSIP_BADPARAMETER;
  return __osip_auth_to_str(value, value->auth_type, value->auth_param, &value->auth_params,
                            auth_fields, AUTH_FIELD_COUNT, dest);
}

const char *osip_authorization_get_param(const osip_authorization_t *value, const char *name) {
  if (value == NULL) return NULL;
  return __osip_auth_get_param(value, &value->auth_params, auth_fields, AUTH_FIELD_COUNT, name);
}

/* deallocates a osip_authorization_t structure.  */
/* INPUT : osip_authorization_t *authorization | authorization. */
void osip_authorization_free(osip_authorization_t *authorization) {
  if (authorization == NULL)
    return;

  osip_free(authorization->auth_type);
  osip_free(authorization->username);
  osip_free(authorization->realm);
  osip_free(authorization->nonce);
  osip_free(authorization->uri);
  osip_free(authorization->response);
  osip_free(authorization->digest);
  osip_free(authorization->algorithm);
  osip_free(authorization->cnonce);
  osip_free(authorization->opaque);
  osip_free(authorization->message_qop);
  osip_free(authorization->nonce_count);
  osip_free(authorization->version);
  osip_free(authorization->targetname);
  osip_free(authorization->gssapi_data);
  osip_free(authorization->crand);
  osip_free(authorization->cnum);
  osip_free(authorization->auth_param);
  __osip_auth_params_free(&authorization->auth_params);
  osip_free(authorization);
}

int osip_authorization_clone(const osip_authorization_t *source, osip_authorization_t **dest) {
  osip_authorization_t *copy;
  size_t index;
  int status;
  if (dest == NULL) return OSIP_BADPARAMETER;
  *dest = NULL;
  if (source == NULL || source->auth_type == NULL) return OSIP_BADPARAMETER;
  status = osip_authorization_init(&copy);
  if (status != OSIP_SUCCESS) return status;
  copy->auth_type = osip_strdup(source->auth_type);
  if (copy->auth_type == NULL) { osip_authorization_free(copy); return OSIP_NOMEM; }
  if (source->auth_param != NULL) {
    copy->auth_param = osip_strdup(source->auth_param);
    if (copy->auth_param == NULL) { osip_authorization_free(copy); return OSIP_NOMEM; }
  }
  for (index = 0; index < AUTH_FIELD_COUNT; ++index) {
    const char *value = *(char *const *) ((const char *) source + auth_fields[index].offset);
    if (value != NULL) {
      char **slot = (char **) ((char *) copy + auth_fields[index].offset);
      *slot = osip_strdup(value);
      if (*slot == NULL) { osip_authorization_free(copy); return OSIP_NOMEM; }
    }
  }
  for (index = 0; index < (size_t) osip_list_size(&source->auth_params); ++index) {
    const osip_generic_param_t *parameter = osip_list_get(&source->auth_params, (int) index);
    osip_generic_param_t *duplicate = NULL;
    status = osip_generic_param_clone(parameter, &duplicate);
    if (status != OSIP_SUCCESS || duplicate == NULL || duplicate->gname == NULL ||
        (parameter->gvalue != NULL && duplicate->gvalue == NULL)) {
      osip_generic_param_free(duplicate);
      osip_authorization_free(copy);
      return status != OSIP_SUCCESS ? status : OSIP_NOMEM;
    }
    status = osip_list_add(&copy->auth_params, duplicate, -1);
    if (status < 0) { osip_generic_param_free(duplicate); osip_authorization_free(copy); return status; }
  }
  *dest = copy;
  return OSIP_SUCCESS;
}


