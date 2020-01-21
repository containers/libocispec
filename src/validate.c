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
#include "runtime_spec_schema_config_schema.h"

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

  if (err) {
    fprintf (stderr, "error in %s: %s\n", file, err);
    exit (EXIT_FAILURE);
  }

  exit (EXIT_SUCCESS);
}
