/* Copyright (C) 2025 Giuseppe Scrivano <giuseppe@scrivano.org>

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

/* Test arrays of mapStringString (BasicMapArrayHandler) */

#include "config.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ocispec/basic_test_map_string_string_array.h"

static int
test_parse_map_string_string_array (void)
{
  parser_error err = NULL;
  basic_test_map_string_string_array *obj = NULL;
  int ret = 0;

  obj = basic_test_map_string_string_array_parse_file ("tests/data/map-string-string-array.json", NULL, &err);
  if (obj == NULL)
    {
      printf ("parse error: %s\n", err ? err : "(null)");
      ret = 1;
      goto out;
    }

  /* Verify we parsed 3 maps */
  if (obj->maps_len != 3)
    {
      printf ("expected 3 maps, got %zu\n", obj->maps_len);
      ret = 2;
      goto out;
    }

  /* Verify first map has 2 entries */
  if (obj->maps[0] == NULL)
    {
      printf ("maps[0] is NULL\n");
      ret = 3;
      goto out;
    }
  if (obj->maps[0]->len != 2)
    {
      printf ("expected maps[0]->len == 2, got %zu\n", obj->maps[0]->len);
      ret = 4;
      goto out;
    }

  /* Verify second map has 2 entries */
  if (obj->maps[1] == NULL)
    {
      printf ("maps[1] is NULL\n");
      ret = 5;
      goto out;
    }
  if (obj->maps[1]->len != 2)
    {
      printf ("expected maps[1]->len == 2, got %zu\n", obj->maps[1]->len);
      ret = 6;
      goto out;
    }

  /* Verify third map is empty */
  if (obj->maps[2] == NULL)
    {
      printf ("maps[2] is NULL\n");
      ret = 7;
      goto out;
    }
  if (obj->maps[2]->len != 0)
    {
      printf ("expected maps[2]->len == 0, got %zu\n", obj->maps[2]->len);
      ret = 8;
      goto out;
    }

  printf ("parse map_string_string array test passed\n");

out:
  free (err);
  free_basic_test_map_string_string_array (obj);
  return ret;
}

static int
test_clone_map_string_string_array (void)
{
  parser_error err = NULL;
  basic_test_map_string_string_array *original = NULL;
  basic_test_map_string_string_array *cloned = NULL;
  char *json_cloned = NULL;
  int ret = 0;
  size_t i;

  original = basic_test_map_string_string_array_parse_file ("tests/data/map-string-string-array.json", NULL, &err);
  if (original == NULL)
    {
      printf ("parse error: %s\n", err ? err : "(null)");
      ret = 1;
      goto out;
    }

  cloned = clone_basic_test_map_string_string_array (original);
  if (cloned == NULL)
    {
      printf ("clone failed\n");
      ret = 2;
      goto out;
    }

  /* Verify array length was cloned */
  if (cloned->maps_len != original->maps_len)
    {
      printf ("maps_len mismatch: original=%zu, cloned=%zu\n",
              original->maps_len, cloned->maps_len);
      ret = 3;
      goto out;
    }

  /* Verify each map was cloned */
  for (i = 0; i < original->maps_len; i++)
    {
      if (cloned->maps[i] == NULL && original->maps[i] != NULL)
        {
          printf ("cloned maps[%zu] is NULL but original is not\n", i);
          ret = 4;
          goto out;
        }
      if (cloned->maps[i] != NULL && original->maps[i] != NULL)
        {
          if (cloned->maps[i]->len != original->maps[i]->len)
            {
              printf ("maps[%zu]->len mismatch: original=%zu, cloned=%zu\n",
                      i, original->maps[i]->len, cloned->maps[i]->len);
              ret = 5;
              goto out;
            }
          /* Verify it's a deep copy */
          if (cloned->maps[i] == original->maps[i])
            {
              printf ("maps[%zu] is same pointer, not a deep copy\n", i);
              ret = 6;
              goto out;
            }
        }
    }

  /* Verify JSON round-trip by reparsing the cloned output and checking data.
     Note: We can't compare JSON strings directly because object key ordering
     may differ between architectures (e.g., s390x big-endian vs x86_64). */
  json_cloned = basic_test_map_string_string_array_generate_json (cloned, NULL, &err);
  if (json_cloned == NULL)
    {
      printf ("generate cloned error: %s\n", err ? err : "(null)");
      ret = 7;
      goto out;
    }

  {
    basic_test_map_string_string_array *reparsed = NULL;
    reparsed = basic_test_map_string_string_array_parse_data (json_cloned, NULL, &err);
    if (reparsed == NULL)
      {
        printf ("reparse cloned JSON error: %s\n", err ? err : "(null)");
        ret = 8;
        goto out;
      }
    if (reparsed->maps_len != original->maps_len)
      {
        printf ("reparsed maps_len mismatch: original=%zu, reparsed=%zu\n",
                original->maps_len, reparsed->maps_len);
        free_basic_test_map_string_string_array (reparsed);
        ret = 9;
        goto out;
      }
    free_basic_test_map_string_string_array (reparsed);
  }

  printf ("clone map_string_string array test passed\n");

out:
  free (err);
  free (json_cloned);
  free_basic_test_map_string_string_array (original);
  free_basic_test_map_string_string_array (cloned);
  return ret;
}

int
main (void)
{
  int ret;

  ret = test_parse_map_string_string_array ();
  if (ret != 0)
    {
      printf ("test_parse_map_string_string_array failed: %d\n", ret);
      return ret;
    }

  ret = test_clone_map_string_string_array ();
  if (ret != 0)
    {
      printf ("test_clone_map_string_string_array failed: %d\n", ret);
      return ret;
    }

  return 0;
}
