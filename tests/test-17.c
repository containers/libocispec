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

/* Test that a JSON string containing a NUL character is rejected.

   JSON allows \u0000 inside a string, but the parsed value is stored as a C
   string, where the first NUL ends it.  Unless rejected, the rest of the
   value is silently dropped -- a mount option "nosuid\u0000,noexec" used to
   become just "nosuid", with no error whatsoever.  */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ocispec/runtime_spec_schema_config_schema.h"

static const char *const configs[] = {
  /* String.  */
  "{\"ociVersion\": \"1.0.0\", \"root\": {\"path\": \"rootfs\\u0000/etc\"}}",

  /* String inside an array of objects.  */
  "{\"ociVersion\": \"1.0.0\", \"mounts\": [{\"destination\": \"/proc\\u0000/sys\", \"type\": \"proc\"}]}",

  /* Array of strings.  */
  "{\"ociVersion\": \"1.0.0\", \"mounts\": [{\"destination\": \"/sys/fs/cgroup\", \"type\": \"cgroup2\","
  " \"options\": [\"nosuid\\u0000,noexec\"]}]}",

  "{\"ociVersion\": \"1.0.0\", \"process\": {\"cwd\": \"/\", \"args\": [\"/bin/sh\", \"-c\\u0000\"]}}",

  /* Map of strings.  */
  "{\"ociVersion\": \"1.0.0\", \"annotations\": {\"key\": \"value\\u0000more\"}}",

  /* NUL as the very first character.  */
  "{\"ociVersion\": \"1.0.0\", \"hostname\": \"\\u0000\"}",
};

int
main ()
{
  runtime_spec_schema_config_schema *config = NULL;
  parser_error err = NULL;
  size_t i;
  int ret = 0;

  for (i = 0; i < sizeof (configs) / sizeof (configs[0]); i++)
    {
      config = runtime_spec_schema_config_schema_parse_data (configs[i], 0, &err);
      if (config != NULL)
        {
          printf ("config #%zu: expected the parse to fail: %s\n", i, configs[i]);
          free_runtime_spec_schema_config_schema (config);
          free (err);
          err = NULL;
          ret = 1;
          continue;
        }

      if (err == NULL)
        {
          printf ("config #%zu: parse failed without setting an error: %s\n", i, configs[i]);
          ret = 1;
          continue;
        }

      printf ("config #%zu rejected: %s\n", i, err);
      free (err);
      err = NULL;
    }

  /* Other escaped characters are fine.  */
  config = runtime_spec_schema_config_schema_parse_data (
      "{\"ociVersion\": \"1.0.0\", \"hostname\": \"a\\u0001b\\u00e9\"}", 0, &err);
  if (config == NULL)
    {
      printf ("valid config rejected: %s\n", err ? err : "(no error)");
      free (err);
      return 1;
    }
  if (strcmp (config->hostname, "a\001b\303\251") != 0)
    {
      printf ("unexpected hostname: %s\n", config->hostname);
      ret = 1;
    }
  free_runtime_spec_schema_config_schema (config);

  return ret;
}
