/* Copyright (C) 2026 Kir Kolyshkin <kolyshkin@gmail.com>

libocispec is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

libocispec is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libocispec.  If not, see <http://www.gnu.org/licenses/>.

*/

/* Test that a JSON null inside an array of objects is rejected.

   make_*() returns NULL without setting *err when the value it was given is
   absent, and callers use that to tell an absent optional field from a
   failure.  A null array element hits the very same code path, so unless the
   array itself reports the error, the failure is mistaken for an absent
   field and the whole enclosing object is silently dropped -- a config with
   a null in "syscalls" used to produce a container with no seccomp filter at
   all, and no error whatsoever.  */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ocispec/runtime_spec_schema_config_schema.h"

static const char *const configs[] = {
  /* Array of objects, nested deep inside the document.  */
  "{\"ociVersion\": \"1.0.0\", \"linux\": {\"seccomp\": {\"defaultAction\": \"SCMP_ACT_ALLOW\","
  " \"syscalls\": [{\"names\": [\"socket\"], \"action\": \"SCMP_ACT_ERRNO\", \"args\": [null]}]}}}",

  /* Array of objects, one level up.  */
  "{\"ociVersion\": \"1.0.0\", \"linux\": {\"seccomp\": {\"defaultAction\": \"SCMP_ACT_ALLOW\","
  " \"syscalls\": [null]}}}",

  /* Top level array of objects.  */
  "{\"ociVersion\": \"1.0.0\", \"mounts\": [null]}",

  /* Array of objects inside an optional object.  */
  "{\"ociVersion\": \"1.0.0\", \"hooks\": {\"prestart\": [null]}}",

  /* Array of objects inside the linux block.  */
  "{\"ociVersion\": \"1.0.0\", \"linux\": {\"namespaces\": [null]}}",

  "{\"ociVersion\": \"1.0.0\", \"linux\": {\"devices\": [null]}}",

  "{\"ociVersion\": \"1.0.0\", \"linux\": {\"uidMappings\": [null]}}",
};

int
main ()
{
  size_t i;
  int ret = 0;

  for (i = 0; i < sizeof (configs) / sizeof (configs[0]); i++)
    {
      runtime_spec_schema_config_schema *config = NULL;
      parser_error err = NULL;

      config = runtime_spec_schema_config_schema_parse_data (configs[i], 0, &err);
      if (config != NULL)
        {
          printf ("config #%zu: expected the parse to fail: %s\n", i, configs[i]);
          free_runtime_spec_schema_config_schema (config);
          free (err);
          ret = 1;
          continue;
        }

      /* A NULL error would be reported as an absent field by the caller,
         which is exactly the bug this test guards against.  */
      if (err == NULL)
        {
          printf ("config #%zu: parse failed without setting an error: %s\n", i, configs[i]);
          ret = 1;
          continue;
        }

      printf ("config #%zu rejected: %s\n", i, err);
      free (err);
    }

  return ret;
}
