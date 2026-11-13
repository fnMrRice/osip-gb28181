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
  {"realm", offsetof(osip_www_authenticate_t, realm)},
  {"domain", offsetof(osip_www_authenticate_t, domain)},
  {"nonce", offsetof(osip_www_authenticate_t, nonce)},
  {"opaque", offsetof(osip_www_authenticate_t, opaque)},
  {"stale", offsetof(osip_www_authenticate_t, stale)},
  {"algorithm", offsetof(osip_www_authenticate_t, algorithm)},
  {"qop", offsetof(osip_www_authenticate_t, qop_options)},
  {"version", offsetof(osip_www_authenticate_t, version)},
  {"targetname", offsetof(osip_www_authenticate_t, targetname)},
  {"gssapi-data", offsetof(osip_www_authenticate_t, gssapi_data)},
};
#define AUTH_FIELD_COUNT (sizeof(auth_fields) / sizeof(auth_fields[0]))


int osip_www_authenticate_init(osip_www_authenticate_t **dest) {
  *dest = (osip_www_authenticate_t *) osip_malloc(sizeof(osip_www_authenticate_t));

  if (*dest == NULL)
    return OSIP_NOMEM;

  memset(*dest, 0, sizeof(osip_www_authenticate_t));
  osip_list_init(&(*dest)->auth_params);
  return OSIP_SUCCESS;
}

/* fills the www-authenticate header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int osip_message_set_www_authenticate(osip_message_t *sip, const char *hvalue) {
  osip_www_authenticate_t *www_authenticate;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return OSIP_SUCCESS;

  if (sip == NULL)
    return OSIP_BADPARAMETER;

  i = osip_www_authenticate_init(&www_authenticate);

  if (i != 0)
    return i;

  i = osip_www_authenticate_parse(www_authenticate, hvalue);

  if (i != 0) {
    osip_www_authenticate_free(www_authenticate);
    return i;
  }

  sip->message_property = 2;
  i = osip_list_add(&sip->www_authenticates, www_authenticate, -1);
  if (i < 0) { osip_www_authenticate_free(www_authenticate); return i; }
  return OSIP_SUCCESS;
}

int __osip_quoted_string_set(const char *name, const char *str, char **result, const char **next) {
  *next = str;

  if (*result != NULL)
    return OSIP_SUCCESS; /* already parsed */

  *next = NULL;

  while ((' ' == *str) || ('\t' == *str) || (',' == *str))
    if (*str)
      str++;

    else
      return OSIP_SYNTAXERROR; /* bad header format */

  if (osip_strncasecmp(name, str, strlen(name)) == 0) {
    const char *quote1;
    const char *quote2;
    const char *tmp;
    const char *hack = strchr(str, '=');

    if (hack == NULL)
      return OSIP_SYNTAXERROR;

    while (' ' == *(hack - 1)) /* get rid of extra spaces */
      hack--;

    if ((size_t)(hack - str) != strlen(name)) {
      *next = str;
      return OSIP_SUCCESS;
    }

    quote1 = __osip_quote_find(str);

    if (quote1 == NULL)
      return OSIP_SYNTAXERROR; /* bad header format... */

    quote2 = __osip_quote_find(quote1 + 1);

    if (quote2 == NULL)
      return OSIP_SYNTAXERROR; /* bad header format... */

    if (quote2 - quote1 == 1) {
      /* this is a special case! The quote contains nothing! */
      /* example:   Digest opaque="",cnonce=""               */
      /* in this case, we just forget the parameter... this  */
      /* this should prevent from user manipulating empty    */
      /* strings */
      tmp = quote2 + 1; /* next element start here */
      tmp += strspn(tmp, " \t");
      tmp += strspn(tmp, "\n\r");
      *next = NULL;

      if (*tmp == '\0') /* end of header detected */
        return OSIP_SUCCESS;

      if (*tmp != '\t' && *tmp != ' ')
        /* LWS here ? */
        *next = tmp;

      else { /* it is: skip it... */
        tmp += strspn(tmp, " \t");

        if (*tmp == '\0') /* end of header detected */
          return OSIP_SUCCESS;

        *next = tmp;
      }

      return OSIP_SUCCESS;
    }

    *result = (char *) osip_malloc(quote2 - quote1 + 3);

    if (*result == NULL)
      return OSIP_NOMEM;

    osip_strncpy(*result, quote1, quote2 - quote1 + 1);
    tmp = quote2 + 1; /* next element start here */
    tmp += strspn(tmp, " \t");
    tmp += strspn(tmp, "\n\r");
    *next = NULL;

    if (*tmp == '\0') /* end of header detected */
      return OSIP_SUCCESS;

    if (*tmp != '\t' && *tmp != ' ')
      /* LWS here ? */
      *next = tmp;

    else { /* it is: skip it... */
      tmp += strspn(tmp, " \t");

      if (*tmp == '\0') /* end of header detected */
        return OSIP_SUCCESS;

      *next = tmp;
    }

  } else
    *next = str; /* wrong header asked! */

  return OSIP_SUCCESS;
}

int __osip_token_set(const char *name, const char *str, char **result, const char **next) {
  const char *beg;
  const char *tmp;

  *next = str;

  if (*result != NULL)
    return OSIP_SUCCESS; /* already parsed */

  *next = NULL;

  beg = strchr(str, '=');

  if (beg == NULL)
    return OSIP_SYNTAXERROR; /* bad header format... */

  if (strlen(str) < 6)
    return OSIP_SUCCESS; /* end of header... */

  while ((' ' == *str) || ('\t' == *str) || (',' == *str))
    if (*str)
      str++;

    else
      return OSIP_SYNTAXERROR; /* bad header format */

  if (osip_strncasecmp(name, str, strlen(name)) == 0) {
    const char *end;

    end = strchr(str, ',');

    if (end == NULL)
      end = str + strlen(str); /* This is the end of the header */

    if (end - beg < 2)
      return OSIP_SYNTAXERROR;

    *result = (char *) osip_malloc(end - beg);

    if (*result == NULL)
      return OSIP_NOMEM;

    osip_clrncpy(*result, beg + 1, end - beg - 1);

    /* make sure the element does not contain more parameter */
    tmp = (*end) ? (end + 1) : end;
    tmp += strspn(tmp, " \t");
    tmp += strspn(tmp, "\n\r");
    *next = NULL;

    if (*tmp == '\0') /* end of header detected */
      return OSIP_SUCCESS;

    if (*tmp != '\t' && *tmp != ' ')
      /* LWS here ? */
      *next = tmp;

    else { /* it is: skip it... */
      tmp += strspn(tmp, " \t");

      if (*tmp == '\0') /* end of header detected */
        return OSIP_SUCCESS;

      *next = tmp;
    }

  } else
    *next = str; /* next element start here */

  return OSIP_SUCCESS;
}

/* fills the www-authenticate strucuture.                      */
/* INPUT : char *hvalue | value of header.         */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
/* TODO:
   digest-challenge tken has no order preference??
   verify many situations (extra SP....)
*/
int osip_www_authenticate_parse(osip_www_authenticate_t *value, const char *text) {
  if (value == NULL) return OSIP_BADPARAMETER;
  return __osip_auth_parse(value, &value->auth_type, &value->auth_param, &value->auth_params,
                           auth_fields, AUTH_FIELD_COUNT, text);
}

#ifndef MINISIZE
/* returns the www_authenticate header.            */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
int osip_message_get_www_authenticate(const osip_message_t *sip, int pos, osip_www_authenticate_t **dest) {
  osip_www_authenticate_t *www_authenticate;

  *dest = NULL;

  if (osip_list_size(&sip->www_authenticates) <= pos)
    return OSIP_UNDEFINED_ERROR; /* does not exist */

  www_authenticate = (osip_www_authenticate_t *) osip_list_get(&sip->www_authenticates, pos);

  *dest = www_authenticate;
  return pos;
}
#endif

char *osip_www_authenticate_get_auth_type(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->auth_type;
}

void osip_www_authenticate_set_auth_type(osip_www_authenticate_t *www_authenticate, char *auth_type) {
  www_authenticate->auth_type = (char *) auth_type;
}

char *osip_www_authenticate_get_realm(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->realm;
}

void osip_www_authenticate_set_realm(osip_www_authenticate_t *www_authenticate, char *realm) {
  www_authenticate->realm = (char *) realm;
}

char *osip_www_authenticate_get_domain(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->domain;
}

void osip_www_authenticate_set_domain(osip_www_authenticate_t *www_authenticate, char *domain) {
  www_authenticate->domain = (char *) domain;
}

char *osip_www_authenticate_get_nonce(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->nonce;
}

void osip_www_authenticate_set_nonce(osip_www_authenticate_t *www_authenticate, char *nonce) {
  www_authenticate->nonce = (char *) nonce;
}

char *osip_www_authenticate_get_stale(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->stale;
}

void osip_www_authenticate_set_stale(osip_www_authenticate_t *www_authenticate, char *stale) {
  www_authenticate->stale = (char *) stale;
}

char *osip_www_authenticate_get_opaque(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->opaque;
}

void osip_www_authenticate_set_opaque(osip_www_authenticate_t *www_authenticate, char *opaque) {
  www_authenticate->opaque = (char *) opaque;
}

char *osip_www_authenticate_get_algorithm(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->algorithm;
}

void osip_www_authenticate_set_algorithm(osip_www_authenticate_t *www_authenticate, char *algorithm) {
  www_authenticate->algorithm = (char *) algorithm;
}

char *osip_www_authenticate_get_qop_options(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->qop_options;
}

void osip_www_authenticate_set_qop_options(osip_www_authenticate_t *www_authenticate, char *qop_options) {
  www_authenticate->qop_options = (char *) qop_options;
}

char *osip_www_authenticate_get_version(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->version;
}

void osip_www_authenticate_set_version(osip_www_authenticate_t *www_authenticate, char *version) {
  www_authenticate->version = (char *) version;
}

char *osip_www_authenticate_get_targetname(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->targetname;
}

void osip_www_authenticate_set_targetname(osip_www_authenticate_t *www_authenticate, char *targetname) {
  www_authenticate->targetname = (char *) targetname;
}

char *osip_www_authenticate_get_gssapi_data(osip_www_authenticate_t *www_authenticate) {
  return www_authenticate->gssapi_data;
}

void osip_www_authenticate_set_gssapi_data(osip_www_authenticate_t *www_authenticate, char *gssapi_data) {
  www_authenticate->gssapi_data = (char *) gssapi_data;
}

/* returns the www_authenticate header as a string.          */
/* INPUT : osip_www_authenticate_t *www_authenticate | www_authenticate header.  */
/* returns null on error. */
int osip_www_authenticate_to_str(const osip_www_authenticate_t *value, char **dest) {
  if (value == NULL || dest == NULL) return OSIP_BADPARAMETER;
  return __osip_auth_to_str(value, value->auth_type, value->auth_param, &value->auth_params,
                            auth_fields, AUTH_FIELD_COUNT, dest);
}

const char *osip_www_authenticate_get_param(const osip_www_authenticate_t *value, const char *name) {
  if (value == NULL) return NULL;
  return __osip_auth_get_param(value, &value->auth_params, auth_fields, AUTH_FIELD_COUNT, name);
}

/* deallocates a osip_www_authenticate_t structure.  */
/* INPUT : osip_www_authenticate_t *www_authenticate | www_authenticate. */
void osip_www_authenticate_free(osip_www_authenticate_t *www_authenticate) {
  if (www_authenticate == NULL)
    return;

  osip_free(www_authenticate->auth_type);
  osip_free(www_authenticate->realm);
  osip_free(www_authenticate->domain);
  osip_free(www_authenticate->nonce);
  osip_free(www_authenticate->opaque);
  osip_free(www_authenticate->stale);
  osip_free(www_authenticate->algorithm);
  osip_free(www_authenticate->qop_options);
  osip_free(www_authenticate->version);
  osip_free(www_authenticate->targetname);
  osip_free(www_authenticate->gssapi_data);

  osip_free(www_authenticate->auth_param);
  __osip_auth_params_free(&www_authenticate->auth_params);
  osip_free(www_authenticate);
}

int osip_www_authenticate_clone(const osip_www_authenticate_t *source, osip_www_authenticate_t **dest) {
  osip_www_authenticate_t *copy;
  size_t index;
  int status;
  if (dest == NULL) return OSIP_BADPARAMETER;
  *dest = NULL;
  if (source == NULL || source->auth_type == NULL) return OSIP_BADPARAMETER;
  status = osip_www_authenticate_init(&copy);
  if (status != OSIP_SUCCESS) return status;
  copy->auth_type = osip_strdup(source->auth_type);
  if (copy->auth_type == NULL) { osip_www_authenticate_free(copy); return OSIP_NOMEM; }
  if (source->auth_param != NULL) {
    copy->auth_param = osip_strdup(source->auth_param);
    if (copy->auth_param == NULL) { osip_www_authenticate_free(copy); return OSIP_NOMEM; }
  }
  for (index = 0; index < AUTH_FIELD_COUNT; ++index) {
    const char *value = *(char *const *) ((const char *) source + auth_fields[index].offset);
    if (value != NULL) {
      char **slot = (char **) ((char *) copy + auth_fields[index].offset);
      *slot = osip_strdup(value);
      if (*slot == NULL) { osip_www_authenticate_free(copy); return OSIP_NOMEM; }
    }
  }
  for (index = 0; index < (size_t) osip_list_size(&source->auth_params); ++index) {
    const osip_generic_param_t *parameter = osip_list_get(&source->auth_params, (int) index);
    osip_generic_param_t *duplicate = NULL;
    status = osip_generic_param_clone(parameter, &duplicate);
    if (status != OSIP_SUCCESS || duplicate == NULL || duplicate->gname == NULL ||
        (parameter->gvalue != NULL && duplicate->gvalue == NULL)) {
      osip_generic_param_free(duplicate);
      osip_www_authenticate_free(copy);
      return status != OSIP_SUCCESS ? status : OSIP_NOMEM;
    }
    status = osip_list_add(&copy->auth_params, duplicate, -1);
    if (status < 0) { osip_generic_param_free(duplicate); osip_www_authenticate_free(copy); return status; }
  }
  *dest = copy;
  return OSIP_SUCCESS;
}


