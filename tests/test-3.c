/* Copyright (C) 2017 Wang Long <w@laoqinren.net>

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
#include "oci_image_spec.h"

int
main (int argc, char *argv[])
{
  oci_parser_error err;
  oci_image *image = oci_image_parse_file ("tests/image_config.json", 0, &err);

  if (image == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  if (strcmp (image->author, "Alyssa P. Hacker <alyspdev@example.com>"))
    exit (5);
  if (strcmp (image->created, "2015-10-31T22:22:56.015925234Z"))
    exit (5);
  if (strcmp (image->os, "linux"))
    exit (5);
  if (strcmp (image->architecture, "amd64"))
    exit (5);
  if (strcmp (image->config->User, "1:1"))
    exit (5);
  if (strcmp (image->config->Env[1], "FOO=docker_is_a_really"))
    exit (5);
  if (strcmp (image->config->Entrypoint[0], "/bin/sh"))
    exit (5);
  if (image->config->Volumes_len != 2)
    exit (5);
  if (strcmp (image->config->Volumes[0], "/var/job-result-data"))
    exit (5);
  if (strcmp (image->config->Volumes[1], "/var/log/my-app-logs"))
    exit (5);
  free_oci_image (image);
  exit (0);
}
