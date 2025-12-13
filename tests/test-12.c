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

/* Test clone round-trip: parse -> clone -> generate -> parse -> compare */

#include "config.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ocispec/runtime_spec_schema_config_schema.h"

static int
test_clone_roundtrip (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *original = NULL;
  runtime_spec_schema_config_schema *cloned = NULL;
  runtime_spec_schema_config_schema *reparsed = NULL;
  char *json_from_original = NULL;
  char *json_from_clone = NULL;
  int ret = 0;

  /* Parse original */
  original = runtime_spec_schema_config_schema_parse_file ("tests/data/config.json", 0, &err);
  if (original == NULL)
    {
      printf ("parse error: %s\n", err);
      ret = 1;
      goto out;
    }

  /* Clone it */
  cloned = clone_runtime_spec_schema_config_schema (original);
  if (cloned == NULL)
    {
      printf ("clone failed (original hostname=%s, ociVersion=%s)\n",
              original->hostname ? original->hostname : "(null)",
              original->oci_version ? original->oci_version : "(null)");
      ret = 2;
      goto out;
    }

  /* Generate JSON from both */
  json_from_original = runtime_spec_schema_config_schema_generate_json (original, 0, &err);
  if (json_from_original == NULL)
    {
      printf ("generate from original error: %s\n", err);
      ret = 3;
      goto out;
    }

  json_from_clone = runtime_spec_schema_config_schema_generate_json (cloned, 0, &err);
  if (json_from_clone == NULL)
    {
      printf ("generate from clone error: %s\n", err);
      ret = 4;
      goto out;
    }

  /* The generated JSON should be identical */
  if (strcmp (json_from_original, json_from_clone) != 0)
    {
      printf ("JSON mismatch between original and clone\n");
      printf ("Original:\n%s\n", json_from_original);
      printf ("Clone:\n%s\n", json_from_clone);
      ret = 5;
      goto out;
    }

  /* Verify we can parse the cloned output */
  reparsed = runtime_spec_schema_config_schema_parse_data (json_from_clone, 0, &err);
  if (reparsed == NULL)
    {
      printf ("reparse error: %s\n", err);
      ret = 6;
      goto out;
    }

  /* Verify key fields match */
  if (strcmp (original->hostname, cloned->hostname) != 0)
    {
      printf ("hostname mismatch\n");
      ret = 7;
      goto out;
    }

  if (strcmp (original->process->cwd, cloned->process->cwd) != 0)
    {
      printf ("cwd mismatch\n");
      ret = 8;
      goto out;
    }

  if (original->process->user->uid != cloned->process->user->uid)
    {
      printf ("uid mismatch\n");
      ret = 9;
      goto out;
    }

  if (original->linux->namespaces_len != cloned->linux->namespaces_len)
    {
      printf ("namespaces_len mismatch\n");
      ret = 10;
      goto out;
    }

  printf ("clone roundtrip test passed\n");

out:
  free (err);
  free (json_from_original);
  free (json_from_clone);
  free_runtime_spec_schema_config_schema (original);
  free_runtime_spec_schema_config_schema (cloned);
  free_runtime_spec_schema_config_schema (reparsed);
  return ret;
}

static int
test_modify_clone_independence (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *original = NULL;
  runtime_spec_schema_config_schema *cloned = NULL;
  int ret = 0;
  const char *original_hostname;

  original = runtime_spec_schema_config_schema_parse_file ("tests/data/config.json", 0, &err);
  if (original == NULL)
    {
      printf ("parse error: %s\n", err);
      ret = 1;
      goto out;
    }

  original_hostname = original->hostname;

  cloned = clone_runtime_spec_schema_config_schema (original);
  if (cloned == NULL)
    {
      printf ("clone failed\n");
      ret = 2;
      goto out;
    }

  /* Modify the clone */
  free (cloned->hostname);
  cloned->hostname = strdup ("modified-hostname");
  if (cloned->hostname == NULL)
    {
      printf ("strdup failed\n");
      ret = 3;
      goto out;
    }

  /* Original should be unchanged */
  if (strcmp (original->hostname, original_hostname) != 0)
    {
      printf ("original was modified when clone was changed\n");
      ret = 4;
      goto out;
    }

  if (strcmp (cloned->hostname, "modified-hostname") != 0)
    {
      printf ("clone modification failed\n");
      ret = 5;
      goto out;
    }

  printf ("clone independence test passed\n");

out:
  free (err);
  free_runtime_spec_schema_config_schema (original);
  free_runtime_spec_schema_config_schema (cloned);
  return ret;
}

static int
test_present_flags (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *config = NULL;
  int ret = 0;

  config = runtime_spec_schema_config_schema_parse_file ("tests/data/config.json", 0, &err);
  if (config == NULL)
    {
      printf ("parse error: %s\n", err);
      ret = 1;
      goto out;
    }

  /* Check that present flags are set correctly */
  if (!config->process->terminal_present)
    {
      printf ("terminal_present should be true\n");
      ret = 2;
      goto out;
    }

  if (!config->process->user->uid_present)
    {
      printf ("uid_present should be true\n");
      ret = 3;
      goto out;
    }

  /* gid is not set in the test data */
  if (config->process->user->gid_present)
    {
      printf ("gid_present should be false\n");
      ret = 4;
      goto out;
    }

  /* Verify numeric values */
  if (config->process->user->uid != 101)
    {
      printf ("uid should be 101, got %u\n", config->process->user->uid);
      ret = 5;
      goto out;
    }

  printf ("present flags test passed\n");

out:
  free (err);
  free_runtime_spec_schema_config_schema (config);
  return ret;
}

static int
test_array_cloning (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *original = NULL;
  runtime_spec_schema_config_schema *cloned = NULL;
  int ret = 0;
  size_t i;

  original = runtime_spec_schema_config_schema_parse_file ("tests/data/config.json", 0, &err);
  if (original == NULL)
    {
      printf ("parse error: %s\n", err);
      ret = 1;
      goto out;
    }

  cloned = clone_runtime_spec_schema_config_schema (original);
  if (cloned == NULL)
    {
      printf ("clone failed\n");
      ret = 2;
      goto out;
    }

  /* Verify array lengths match */
  if (original->process->args_len != cloned->process->args_len)
    {
      printf ("args_len mismatch\n");
      ret = 3;
      goto out;
    }

  /* Verify array contents match */
  for (i = 0; i < original->process->args_len; i++)
    {
      if (strcmp (original->process->args[i], cloned->process->args[i]) != 0)
        {
          printf ("args[%zu] mismatch\n", i);
          ret = 4;
          goto out;
        }
    }

  /* Verify mounts array */
  if (original->mounts_len != cloned->mounts_len)
    {
      printf ("mounts_len mismatch\n");
      ret = 5;
      goto out;
    }

  for (i = 0; i < original->mounts_len; i++)
    {
      if (strcmp (original->mounts[i]->destination, cloned->mounts[i]->destination) != 0)
        {
          printf ("mounts[%zu]->destination mismatch\n", i);
          ret = 6;
          goto out;
        }
    }

  printf ("array cloning test passed\n");

out:
  free (err);
  free_runtime_spec_schema_config_schema (original);
  free_runtime_spec_schema_config_schema (cloned);
  return ret;
}

int
main (void)
{
  int ret;

  ret = test_clone_roundtrip ();
  if (ret != 0)
    {
      printf ("test_clone_roundtrip failed: %d\n", ret);
      return ret;
    }

  ret = test_modify_clone_independence ();
  if (ret != 0)
    {
      printf ("test_modify_clone_independence failed: %d\n", ret);
      return ret;
    }

  ret = test_present_flags ();
  if (ret != 0)
    {
      printf ("test_present_flags failed: %d\n", ret);
      return ret;
    }

  ret = test_array_cloning ();
  if (ret != 0)
    {
      printf ("test_array_cloning failed: %d\n", ret);
      return ret;
    }

  return 0;
}
