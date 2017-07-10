/* Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>

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

#include "config.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include "spec.h"

int
main (int argc, char *argv[])
{
  oci_parser_error err;
  oci_container_container *container;
  const char *file = "config.json";
  struct libocispec_context ctx;

  if (argc > 1)
    file = argv[1];

  ctx.options = LIBOCISPEC_OPTIONS_STRICT;

  container = oci_parse_file (file, &ctx, &err);
  if (container)
    free_oci_container_container (container);

  if (err)
    error (EXIT_FAILURE, 0, "error in %s: %s", file, err);

  exit (0);
}
