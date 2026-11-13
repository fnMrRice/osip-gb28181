/* Generic authentication parameters, maintained against GNU oSIP2.
 * Distributed under the same LGPL-2.1-or-later terms as oSIP2. */
#ifndef OSIP_AUTH_PARAM_INTERNAL_H
#define OSIP_AUTH_PARAM_INTERNAL_H
#include <stddef.h>

typedef struct __osip_auth_field {
  const char *name;
  size_t offset;
} __osip_auth_field_t;

int __osip_auth_parse(void *object, char **scheme, char **token68, osip_list_t *extensions,
                      const __osip_auth_field_t *fields, size_t count, const char *text);
int __osip_auth_to_str(const void *object, const char *scheme, const char *token68,
                       const osip_list_t *extensions, const __osip_auth_field_t *fields,
                       size_t count, char **dest);
const char *__osip_auth_get_param(const void *object, const osip_list_t *extensions,
                                  const __osip_auth_field_t *fields, size_t count, const char *name);
void __osip_auth_params_free(osip_list_t *extensions);
#endif
