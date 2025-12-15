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

/* Test error handling and edge cases */

#include "config.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ocispec/runtime_spec_schema_config_schema.h"
#include "ocispec/image_spec_schema_config_schema.h"

static int
test_parse_invalid_json (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *config = NULL;
  int ret = 0;

  /* Parse invalid JSON */
  config = runtime_spec_schema_config_schema_parse_data ("{invalid json", 0, &err);
  if (config != NULL)
    {
      printf ("expected parse to fail for invalid JSON\n");
      free_runtime_spec_schema_config_schema (config);
      ret = 1;
      goto out;
    }

  /* Error should be set */
  if (err == NULL)
    {
      printf ("expected error to be set\n");
      ret = 2;
      goto out;
    }

  printf ("parse invalid json test passed (error: %s)\n", err);

out:
  free (err);
  return ret;
}

static int
test_parse_minimal_json (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *config = NULL;
  char *json_buf = NULL;
  int ret = 0;
  /* Minimal valid config - ociVersion is required */
  const char *minimal_json = "{\"ociVersion\": \"1.0.0\"}";

  config = runtime_spec_schema_config_schema_parse_data (minimal_json, 0, &err);
  if (config == NULL)
    {
      printf ("parse minimal object failed: %s\n", err);
      ret = 1;
      goto out;
    }

  if (config->oci_version == NULL || strcmp (config->oci_version, "1.0.0") != 0)
    {
      printf ("ociVersion mismatch\n");
      ret = 2;
      goto out;
    }

  /* Generate JSON from minimal object */
  json_buf = runtime_spec_schema_config_schema_generate_json (config, 0, &err);
  if (json_buf == NULL)
    {
      printf ("generate from minimal object failed: %s\n", err);
      ret = 3;
      goto out;
    }

  printf ("parse minimal json test passed\n");

out:
  free (err);
  free (json_buf);
  free_runtime_spec_schema_config_schema (config);
  return ret;
}

static int
test_parse_nonexistent_file (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *config = NULL;
  int ret = 0;

  config = runtime_spec_schema_config_schema_parse_file ("/nonexistent/path/config.json", 0, &err);
  if (config != NULL)
    {
      printf ("expected parse to fail for nonexistent file\n");
      free_runtime_spec_schema_config_schema (config);
      ret = 1;
      goto out;
    }

  if (err == NULL)
    {
      printf ("expected error to be set\n");
      ret = 2;
      goto out;
    }

  printf ("parse nonexistent file test passed (error: %s)\n", err);

out:
  free (err);
  return ret;
}

static int
test_null_input (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *config = NULL;
  int ret = 0;

  /* Parse NULL data should fail gracefully */
  config = runtime_spec_schema_config_schema_parse_data (NULL, 0, &err);
  if (config != NULL)
    {
      printf ("expected parse to fail for NULL input\n");
      free_runtime_spec_schema_config_schema (config);
      ret = 1;
      goto out;
    }

  printf ("null input test passed\n");

out:
  free (err);
  return ret;
}

static int
test_empty_arrays (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *config = NULL;
  char *json_buf = NULL;
  int ret = 0;
  const char *json_with_empty_arrays = "{"
    "\"ociVersion\": \"1.0.0\","
    "\"process\": {"
    "  \"args\": [],"
    "  \"env\": [],"
    "  \"cwd\": \"/\""
    "},"
    "\"root\": {\"path\": \"rootfs\"}"
    "}";

  config = runtime_spec_schema_config_schema_parse_data (json_with_empty_arrays, 0, &err);
  if (config == NULL)
    {
      printf ("parse with empty arrays failed: %s\n", err);
      ret = 1;
      goto out;
    }

  /* Verify empty arrays are handled correctly */
  if (config->process->args_len != 0)
    {
      printf ("expected args_len to be 0, got %zu\n", config->process->args_len);
      ret = 2;
      goto out;
    }

  if (config->process->env_len != 0)
    {
      printf ("expected env_len to be 0, got %zu\n", config->process->env_len);
      ret = 3;
      goto out;
    }

  /* Generate JSON should work */
  json_buf = runtime_spec_schema_config_schema_generate_json (config, 0, &err);
  if (json_buf == NULL)
    {
      printf ("generate with empty arrays failed: %s\n", err);
      ret = 4;
      goto out;
    }

  printf ("empty arrays test passed\n");

out:
  free (err);
  free (json_buf);
  free_runtime_spec_schema_config_schema (config);
  return ret;
}

static int
test_string_with_special_chars (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *config = NULL;
  runtime_spec_schema_config_schema *reparsed = NULL;
  char *json_buf = NULL;
  int ret = 0;
  const char *json_with_special = "{"
    "\"ociVersion\": \"1.0.0\","
    "\"hostname\": \"host\\nwith\\nnewlines\","
    "\"process\": {"
    "  \"args\": [\"echo\", \"hello\\tworld\"],"
    "  \"cwd\": \"/path/with spaces/and\\\"quotes\\\"\""
    "},"
    "\"root\": {\"path\": \"rootfs\"}"
    "}";

  config = runtime_spec_schema_config_schema_parse_data (json_with_special, 0, &err);
  if (config == NULL)
    {
      printf ("parse with special chars failed: %s\n", err);
      ret = 1;
      goto out;
    }

  /* Verify special characters are preserved */
  if (strstr (config->hostname, "\n") == NULL)
    {
      printf ("newline not preserved in hostname\n");
      ret = 2;
      goto out;
    }

  /* Generate and reparse to verify round-trip */
  json_buf = runtime_spec_schema_config_schema_generate_json (config, 0, &err);
  if (json_buf == NULL)
    {
      printf ("generate with special chars failed: %s\n", err);
      ret = 3;
      goto out;
    }

  reparsed = runtime_spec_schema_config_schema_parse_data (json_buf, 0, &err);
  if (reparsed == NULL)
    {
      printf ("reparse with special chars failed: %s\n", err);
      ret = 4;
      goto out;
    }

  if (strcmp (config->hostname, reparsed->hostname) != 0)
    {
      printf ("hostname mismatch after round-trip\n");
      ret = 5;
      goto out;
    }

  printf ("string with special chars test passed\n");

out:
  free (err);
  free (json_buf);
  free_runtime_spec_schema_config_schema (config);
  free_runtime_spec_schema_config_schema (reparsed);
  return ret;
}

static int
test_large_numbers (void)
{
  parser_error err = NULL;
  runtime_spec_schema_config_schema *config = NULL;
  runtime_spec_schema_config_schema *reparsed = NULL;
  char *json_buf = NULL;
  int ret = 0;
  const char *json_with_large_nums = "{"
    "\"ociVersion\": \"1.0.0\","
    "\"process\": {"
    "  \"args\": [\"test\"],"
    "  \"cwd\": \"/\","
    "  \"user\": {\"uid\": 4294967295, \"gid\": 4294967295}"
    "},"
    "\"root\": {\"path\": \"rootfs\"}"
    "}";

  config = runtime_spec_schema_config_schema_parse_data (json_with_large_nums, 0, &err);
  if (config == NULL)
    {
      printf ("parse with large numbers failed: %s\n", err);
      ret = 1;
      goto out;
    }

  /* Generate and reparse */
  json_buf = runtime_spec_schema_config_schema_generate_json (config, 0, &err);
  if (json_buf == NULL)
    {
      printf ("generate with large numbers failed: %s\n", err);
      ret = 2;
      goto out;
    }

  reparsed = runtime_spec_schema_config_schema_parse_data (json_buf, 0, &err);
  if (reparsed == NULL)
    {
      printf ("reparse with large numbers failed: %s\n", err);
      ret = 3;
      goto out;
    }

  if (config->process->user->uid != reparsed->process->user->uid)
    {
      printf ("uid mismatch after round-trip\n");
      ret = 4;
      goto out;
    }

  printf ("large numbers test passed\n");

out:
  free (err);
  free (json_buf);
  free_runtime_spec_schema_config_schema (config);
  free_runtime_spec_schema_config_schema (reparsed);
  return ret;
}

static int
test_clone_null (void)
{
  runtime_spec_schema_config_schema *cloned = NULL;
  int ret = 0;

  /* Clone NULL should return NULL */
  cloned = clone_runtime_spec_schema_config_schema (NULL);
  if (cloned != NULL)
    {
      printf ("expected clone of NULL to return NULL\n");
      free_runtime_spec_schema_config_schema (cloned);
      ret = 1;
      goto out;
    }

  printf ("clone null test passed\n");

out:
  return ret;
}

static int
test_free_null (void)
{
  /* Free NULL should not crash */
  free_runtime_spec_schema_config_schema (NULL);
  free_image_spec_schema_config_schema (NULL);

  printf ("free null test passed\n");
  return 0;
}

int
main (void)
{
  int ret;

  ret = test_parse_invalid_json ();
  if (ret != 0)
    {
      printf ("test_parse_invalid_json failed: %d\n", ret);
      return ret;
    }

  ret = test_parse_minimal_json ();
  if (ret != 0)
    {
      printf ("test_parse_minimal_json failed: %d\n", ret);
      return ret;
    }

  ret = test_parse_nonexistent_file ();
  if (ret != 0)
    {
      printf ("test_parse_nonexistent_file failed: %d\n", ret);
      return ret;
    }

  ret = test_null_input ();
  if (ret != 0)
    {
      printf ("test_null_input failed: %d\n", ret);
      return ret;
    }

  ret = test_empty_arrays ();
  if (ret != 0)
    {
      printf ("test_empty_arrays failed: %d\n", ret);
      return ret;
    }

  ret = test_string_with_special_chars ();
  if (ret != 0)
    {
      printf ("test_string_with_special_chars failed: %d\n", ret);
      return ret;
    }

  ret = test_large_numbers ();
  if (ret != 0)
    {
      printf ("test_large_numbers failed: %d\n", ret);
      return ret;
    }

  ret = test_clone_null ();
  if (ret != 0)
    {
      printf ("test_clone_null failed: %d\n", ret);
      return ret;
    }

  ret = test_free_null ();
  if (ret != 0)
    {
      printf ("test_free_null failed: %d\n", ret);
      return ret;
    }

  return 0;
}
