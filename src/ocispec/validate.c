/* Copyright (C) 2017, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>

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

#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ocispec/runtime_spec_schema_config_schema.h"
#include "ocispec/image_spec_schema_config_schema.h"
#include "ocispec/image_spec_schema_image_index_schema.h"
#include "ocispec/image_spec_schema_image_manifest_schema.h"
#include "ocispec/image_spec_schema_image_layout_schema.h"

#ifdef FUZZER

static int fuzzing_mode = -1;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  const char *mode = getenv ("FUZZING_MODE");
  if (mode)
    fuzzing_mode = atoi (mode);
  return 0;
}

static int
fuzz_runtime_config_strict (const uint8_t *buf, size_t len)
{
  runtime_spec_schema_config_schema *container;
  struct parser_context ctx = { .options = OPT_PARSE_STRICT, .errfile = stderr };
  parser_error err = NULL;
  char *json_buf = NULL;

  FILE *s = fmemopen ((void *) buf, len, "r");
  if (s == NULL)
    return 0;

  container = runtime_spec_schema_config_schema_parse_file_stream (s, &ctx, &err);
  fclose (s);

  if (container)
    {
      json_buf = runtime_spec_schema_config_schema_generate_json (container, &ctx, &err);
      if (json_buf)
        {
          runtime_spec_schema_config_schema *reparsed;
          reparsed = runtime_spec_schema_config_schema_parse_data (json_buf, &ctx, &err);
          free_runtime_spec_schema_config_schema (reparsed);
          free (err);
          err = NULL;
          free (json_buf);
        }
      else
        {
          free (err);
          err = NULL;
        }
      free_runtime_spec_schema_config_schema (container);
    }
  else
    {
      free (err);
    }
  return 0;
}

static int
fuzz_runtime_config_fullkey (const uint8_t *buf, size_t len)
{
  runtime_spec_schema_config_schema *container;
  struct parser_context ctx = { .options = OPT_PARSE_FULLKEY, .errfile = stderr };
  parser_error err = NULL;
  char *json_buf = NULL;

  FILE *s = fmemopen ((void *) buf, len, "r");
  if (s == NULL)
    return 0;

  container = runtime_spec_schema_config_schema_parse_file_stream (s, &ctx, &err);
  fclose (s);

  if (container)
    {
      json_buf = runtime_spec_schema_config_schema_generate_json (container, &ctx, &err);
      if (json_buf)
        {
          runtime_spec_schema_config_schema *reparsed;
          reparsed = runtime_spec_schema_config_schema_parse_data (json_buf, &ctx, &err);
          free_runtime_spec_schema_config_schema (reparsed);
          free (err);
          err = NULL;
          free (json_buf);
        }
      else
        {
          free (err);
          err = NULL;
        }
      free_runtime_spec_schema_config_schema (container);
    }
  else
    {
      free (err);
    }
  return 0;
}

static int
fuzz_image_config (const uint8_t *buf, size_t len)
{
  image_spec_schema_config_schema *container;
  struct parser_context ctx = { .options = OPT_PARSE_STRICT, .errfile = stderr };
  parser_error err = NULL;
  char *json_buf = NULL;

  FILE *s = fmemopen ((void *) buf, len, "r");
  if (s == NULL)
    return 0;

  container = image_spec_schema_config_schema_parse_file_stream (s, &ctx, &err);
  fclose (s);

  if (container)
    {
      json_buf = image_spec_schema_config_schema_generate_json (container, &ctx, &err);
      if (json_buf)
        {
          image_spec_schema_config_schema *reparsed;
          reparsed = image_spec_schema_config_schema_parse_data (json_buf, &ctx, &err);
          free_image_spec_schema_config_schema (reparsed);
          free (err);
          err = NULL;
          free (json_buf);
        }
      else
        {
          free (err);
          err = NULL;
        }
      free_image_spec_schema_config_schema (container);
    }
  else
    {
      free (err);
    }
  return 0;
}

static int
fuzz_image_index (const uint8_t *buf, size_t len)
{
  image_spec_schema_image_index_schema *container;
  struct parser_context ctx = { .options = OPT_PARSE_STRICT, .errfile = stderr };
  parser_error err = NULL;
  char *json_buf = NULL;

  FILE *s = fmemopen ((void *) buf, len, "r");
  if (s == NULL)
    return 0;

  container = image_spec_schema_image_index_schema_parse_file_stream (s, &ctx, &err);
  fclose (s);

  if (container)
    {
      json_buf = image_spec_schema_image_index_schema_generate_json (container, &ctx, &err);
      if (json_buf)
        {
          image_spec_schema_image_index_schema *reparsed;
          reparsed = image_spec_schema_image_index_schema_parse_data (json_buf, &ctx, &err);
          free_image_spec_schema_image_index_schema (reparsed);
          free (err);
          err = NULL;
          free (json_buf);
        }
      else
        {
          free (err);
          err = NULL;
        }
      free_image_spec_schema_image_index_schema (container);
    }
  else
    {
      free (err);
    }
  return 0;
}

static int
fuzz_image_manifest (const uint8_t *buf, size_t len)
{
  image_spec_schema_image_manifest_schema *container;
  struct parser_context ctx = { .options = OPT_PARSE_STRICT, .errfile = stderr };
  parser_error err = NULL;
  char *json_buf = NULL;

  FILE *s = fmemopen ((void *) buf, len, "r");
  if (s == NULL)
    return 0;

  container = image_spec_schema_image_manifest_schema_parse_file_stream (s, &ctx, &err);
  fclose (s);

  if (container)
    {
      json_buf = image_spec_schema_image_manifest_schema_generate_json (container, &ctx, &err);
      if (json_buf)
        {
          image_spec_schema_image_manifest_schema *reparsed;
          reparsed = image_spec_schema_image_manifest_schema_parse_data (json_buf, &ctx, &err);
          free_image_spec_schema_image_manifest_schema (reparsed);
          free (err);
          err = NULL;
          free (json_buf);
        }
      else
        {
          free (err);
          err = NULL;
        }
      free_image_spec_schema_image_manifest_schema (container);
    }
  else
    {
      free (err);
    }
  return 0;
}

static int
fuzz_image_layout (const uint8_t *buf, size_t len)
{
  image_spec_schema_image_layout_schema *container;
  struct parser_context ctx = { .options = OPT_PARSE_STRICT, .errfile = stderr };
  parser_error err = NULL;
  char *json_buf = NULL;

  FILE *s = fmemopen ((void *) buf, len, "r");
  if (s == NULL)
    return 0;

  container = image_spec_schema_image_layout_schema_parse_file_stream (s, &ctx, &err);
  fclose (s);

  if (container)
    {
      json_buf = image_spec_schema_image_layout_schema_generate_json (container, &ctx, &err);
      if (json_buf)
        {
          image_spec_schema_image_layout_schema *reparsed;
          reparsed = image_spec_schema_image_layout_schema_parse_data (json_buf, &ctx, &err);
          free_image_spec_schema_image_layout_schema (reparsed);
          free (err);
          err = NULL;
          free (json_buf);
        }
      else
        {
          free (err);
          err = NULL;
        }
      free_image_spec_schema_image_layout_schema (container);
    }
  else
    {
      free (err);
    }
  return 0;
}

static int
fuzz_runtime_config_parse_data (const uint8_t *buf, size_t len)
{
  runtime_spec_schema_config_schema *container;
  struct parser_context ctx = { .options = OPT_PARSE_STRICT, .errfile = stderr };
  parser_error err = NULL;
  char *data;

  data = malloc (len + 1);
  if (data == NULL)
    return 0;

  memcpy (data, buf, len);
  data[len] = '\0';

  container = runtime_spec_schema_config_schema_parse_data (data, &ctx, &err);
  free (data);

  if (container)
    {
      char *json_buf = runtime_spec_schema_config_schema_generate_json (container, &ctx, &err);
      if (json_buf)
        {
          runtime_spec_schema_config_schema *reparsed;
          reparsed = runtime_spec_schema_config_schema_parse_data (json_buf, &ctx, &err);
          free_runtime_spec_schema_config_schema (reparsed);
          free (err);
          err = NULL;
          free (json_buf);
        }
      else
        {
          free (err);
          err = NULL;
        }
      free_runtime_spec_schema_config_schema (container);
    }
  else
    {
      free (err);
    }
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *buf, size_t len)
{
  if (len == 0)
    return 0;

  switch (fuzzing_mode)
    {
    case 0:
      return fuzz_runtime_config_strict (buf, len);
    case 1:
      return fuzz_runtime_config_fullkey (buf, len);
    case 2:
      return fuzz_image_config (buf, len);
    case 3:
      return fuzz_image_index (buf, len);
    case 4:
      return fuzz_image_manifest (buf, len);
    case 5:
      return fuzz_image_layout (buf, len);
    case 6:
      return fuzz_runtime_config_parse_data (buf, len);
    default:
      /* Run all modes.  */
      fuzz_runtime_config_strict (buf, len);
      fuzz_runtime_config_fullkey (buf, len);
      fuzz_image_config (buf, len);
      fuzz_image_index (buf, len);
      fuzz_image_manifest (buf, len);
      fuzz_image_layout (buf, len);
      fuzz_runtime_config_parse_data (buf, len);
      return 0;
    }
}
#endif

#ifndef FUZZER
int
main (int argc, char *argv[])
{
  parser_error err;
  runtime_spec_schema_config_schema *container;
  const char *file = "config.json";
  struct parser_context ctx;

  if (argc > 1)
    file = argv[1];

  ctx.options = OPT_PARSE_STRICT;
  ctx.errfile = stderr;

  container = runtime_spec_schema_config_schema_parse_file (file, &ctx, &err);
  if (container)
    free_runtime_spec_schema_config_schema (container);

  if (err)
    {
      fprintf (stderr, "error in %s: %s\n", file, err);
      free (err);
      exit (EXIT_FAILURE);
    }

  exit (EXIT_SUCCESS);
}
#endif
