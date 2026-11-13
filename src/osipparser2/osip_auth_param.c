/* Generic authentication parameters, maintained against GNU oSIP2.
 * Distributed under the same LGPL-2.1-or-later terms as oSIP2. */
#include <osipparser2/internal.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include "osip_auth_param.h"

static int auth_token(unsigned char value) {
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
         (value >= '0' && value <= '9') ||
         (value != 0 && strchr("!#$%&'*+-.^_`|~", value) != NULL);
}
static const char *auth_skip_space(const char *value) {
  while (*value == ' ' || *value == '\t') ++value;
  return value;
}
static char *auth_copy(const char *start, size_t size) {
  char *result = osip_malloc(size + 1);
  if (result != NULL) {
    memcpy(result, start, size);
    result[size] = '\0';
  }
  return result;
}
static char **auth_slot(void *object, const __osip_auth_field_t *field) {
  return (char **) ((char *) object + field->offset);
}
static const char *auth_value(const void *object, const __osip_auth_field_t *field) {
  return *(char *const *) ((const char *) object + field->offset);
}
const char *__osip_auth_get_param(const void *object, const osip_list_t *extensions,
                                  const __osip_auth_field_t *fields, size_t count, const char *name) {
  size_t index;
  int position;
  if (object == NULL || name == NULL) return NULL;
  for (index = 0; index < count; ++index)
    if (osip_strcasecmp(fields[index].name, name) == 0) return auth_value(object, &fields[index]);
  for (position = 0; position < osip_list_size(extensions); ++position) {
    const osip_generic_param_t *parameter = osip_list_get(extensions, position);
    if (parameter != NULL && osip_strcasecmp(parameter->gname, name) == 0) return parameter->gvalue;
  }
  return NULL;
}
void __osip_auth_params_free(osip_list_t *extensions) {
  while (osip_list_size(extensions) != 0) {
    osip_generic_param_t *parameter = osip_list_get(extensions, 0);
    osip_list_remove(extensions, 0);
    osip_generic_param_free(parameter);
  }
}
static int auth_store(void *object, osip_list_t *extensions, const __osip_auth_field_t *fields,
                       size_t count, const char *name, size_t name_size, const char *value, size_t value_size) {
  char *key = auth_copy(name, name_size);
  char *data;
  size_t index;
  osip_generic_param_t *parameter;
  int status;
  if (key == NULL) return OSIP_NOMEM;
  if (__osip_auth_get_param(object, extensions, fields, count, key) != NULL) {
    osip_free(key);
    return OSIP_SYNTAXERROR;
  }
  data = auth_copy(value, value_size);
  if (data == NULL) { osip_free(key); return OSIP_NOMEM; }
  for (index = 0; index < count; ++index) {
    if (osip_strcasecmp(fields[index].name, key) == 0) {
      *auth_slot(object, &fields[index]) = data;
      osip_free(key);
      return OSIP_SUCCESS;
    }
  }
  status = osip_generic_param_init(&parameter);
  if (status != OSIP_SUCCESS) { osip_free(key); osip_free(data); return status; }
  parameter->gname = key;
  parameter->gvalue = data;
  status = osip_list_add(extensions, parameter, -1);
  if (status < 0) { osip_generic_param_free(parameter); return status; }
  return OSIP_SUCCESS;
}
static int auth_is_token68(const char *text) {
  const char *start = text;
  while ((*text >= 'a' && *text <= 'z') || (*text >= 'A' && *text <= 'Z') ||
         (*text >= '0' && *text <= '9') || (*text && strchr("-._~+/", *text))) ++text;
  if (text == start) return 0;
  while (*text == '=') ++text;
  return *auth_skip_space(text) == '\0';
}
int __osip_auth_parse(void *object, char **scheme, char **token68, osip_list_t *extensions,
                      const __osip_auth_field_t *fields, size_t count, const char *text) {
  const char *cursor;
  const char *start;
  if (object == NULL || text == NULL || *scheme != NULL) return OSIP_BADPARAMETER;
  cursor = auth_skip_space(text);
  start = cursor;
  while (auth_token((unsigned char) *cursor)) ++cursor;
  if (cursor == start || (*cursor != ' ' && *cursor != '\t')) return OSIP_SYNTAXERROR;
  *scheme = auth_copy(start, (size_t) (cursor - start));
  if (*scheme == NULL) return OSIP_NOMEM;
  cursor = auth_skip_space(cursor);
  if (*cursor == '\0') return OSIP_SYNTAXERROR;
  /* Basic and negotiated schemes may carry an opaque token68 credential. */
  if ((osip_strcasecmp(*scheme, "Basic") == 0 || osip_strcasecmp(*scheme, "NTLM") == 0 ||
       osip_strcasecmp(*scheme, "Negotiate") == 0) && auth_is_token68(cursor)) {
    const char *end = cursor + strlen(cursor);
    while (end > cursor && (end[-1] == ' ' || end[-1] == '\t')) --end;
    *token68 = auth_copy(cursor, (size_t) (end - cursor));
    return *token68 == NULL ? OSIP_NOMEM : OSIP_SUCCESS;
  }
  for (;;) {
    const char *name = cursor;
    const char *value;
    const char *end;
    size_t name_size;
    int quoted = 0;
    int status;
    while (auth_token((unsigned char) *cursor)) ++cursor;
    name_size = (size_t) (cursor - name);
    cursor = auth_skip_space(cursor);
    if (name_size == 0 || *cursor != '=') return OSIP_SYNTAXERROR;
    cursor = auth_skip_space(cursor + 1);
    value = cursor;
    if (*cursor == '"') {
      quoted = 1;
      ++cursor;
      while (*cursor && *cursor != '"') {
        unsigned char item = (unsigned char) *cursor++;
        if ((item < 32 && item != '\t') || item == 127) return OSIP_SYNTAXERROR;
        if (item == '\\') {
          item = (unsigned char) *cursor;
          if ((item < 32 && item != '\t') || item == 127) return OSIP_SYNTAXERROR;
          ++cursor;
        }
      }
      if (*cursor != '"') return OSIP_SYNTAXERROR;
      ++cursor;
    } else {
      while (*cursor && *cursor != ',' && *cursor != ' ' && *cursor != '\t') {
        unsigned char item = (unsigned char) *cursor;
        if (item < 33 || item == 127 || item == '"' || item == '=') return OSIP_SYNTAXERROR;
        ++cursor;
      }
      if (cursor == value) return OSIP_SYNTAXERROR;
    }
    end = cursor;
    status = auth_store(object, extensions, fields, count, name, name_size, value, (size_t) (end - value));
    if (status != OSIP_SUCCESS) return status;
    cursor = auth_skip_space(cursor);
    if (*cursor == '\0') return OSIP_SUCCESS;
    if (*cursor == ',') {
      cursor = auth_skip_space(cursor + 1);
      if (*cursor == '\0') return OSIP_SYNTAXERROR;
    } else if (cursor == end && !quoted) return OSIP_SYNTAXERROR;
    /* Spaces and adjacent quoted fields occur in deployed GB35114 messages. */
  }
}
int __osip_auth_to_str(const void *object, const char *scheme, const char *token68,
                       const osip_list_t *extensions, const __osip_auth_field_t *fields,
                       size_t count, char **dest) {
  size_t length;
  size_t index;
  int position;
  int first = 1;
  char *output;
  *dest = NULL;
  if (object == NULL || scheme == NULL) return OSIP_BADPARAMETER;
  if (token68 != NULL) {
    if (!auth_is_token68(token68) || osip_list_size(extensions) != 0) return OSIP_SYNTAXERROR;
    for (index = 0; index < count; ++index)
      if (auth_value(object, &fields[index]) != NULL) return OSIP_SYNTAXERROR;
  }
  length = strlen(scheme) + 1;
  if (token68 != NULL) length += strlen(token68) + 1;
  for (index = 0; index < count; ++index) {
    const char *value = auth_value(object, &fields[index]);
    if (value != NULL) length += strlen(fields[index].name) + strlen(value) + 3;
  }
  for (position = 0; position < osip_list_size(extensions); ++position) {
    const osip_generic_param_t *parameter = osip_list_get(extensions, position);
    int previous;
    if (parameter == NULL || parameter->gname == NULL || parameter->gvalue == NULL) return OSIP_BADPARAMETER;
    for (index = 0; index < count; ++index)
      if (auth_value(object, &fields[index]) != NULL && osip_strcasecmp(fields[index].name, parameter->gname) == 0)
        return OSIP_SYNTAXERROR;
    for (previous = 0; previous < position; ++previous) {
      const osip_generic_param_t *earlier = osip_list_get(extensions, previous);
      if (osip_strcasecmp(earlier->gname, parameter->gname) == 0) return OSIP_SYNTAXERROR;
    }
    length += strlen(parameter->gname) + strlen(parameter->gvalue) + 3;
  }
  *dest = osip_malloc(length);
  if (*dest == NULL) return OSIP_NOMEM;
  output = osip_str_append(*dest, scheme);
  if (token68 != NULL) { output = osip_strn_append(output, " ", 1); output = osip_str_append(output, token68); first = 0; }
  for (index = 0; index < count; ++index) {
    const char *value = auth_value(object, &fields[index]);
    if (value == NULL) continue;
    output = osip_strn_append(output, first ? " " : ", ", first ? 1 : 2);
    first = 0;
    output = osip_str_append(output, fields[index].name);
    output = osip_strn_append(output, "=", 1);
    output = osip_str_append(output, value);
  }
  for (position = 0; position < osip_list_size(extensions); ++position) {
    const osip_generic_param_t *parameter = osip_list_get(extensions, position);
    output = osip_strn_append(output, first ? " " : ", ", first ? 1 : 2);
    first = 0;
    output = osip_str_append(output, parameter->gname);
    output = osip_strn_append(output, "=", 1);
    output = osip_str_append(output, parameter->gvalue);
  }
  return OSIP_SUCCESS;
}
