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
#include "spec.h"

int
main (int argc, char *argv[])
{
  oci_parser_error err;
  oci_container_container *container = oci_parse_file ("tests/config.json", 0, &err);

  if (container == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  if (strcmp (container->hostname, "runc"))
    exit (5);
  if (strcmp (container->process->cwd, "/cwd"))
    exit (5);
  if (container->process->user->uid != 101)
    exit (5);
  if (strcmp (container->process->args[0], "ARGS1"))
    exit (5);
  if (strcmp (container->mounts[0]->destination, "/proc"))
    exit (5);

  free_oci_container_container (container);
  exit (0);
}
