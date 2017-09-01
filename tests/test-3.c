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
#include <oci_image_spec.h>

int
main (int argc, char *argv[])
{
  oci_parser_error err;
  oci_image *image = oci_image_parse_file ("tests/data/image_config.json", 0, &err);
  char *result = NULL;

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
  if (strcmp (image->config->user, "1:1"))
    exit (5);
  if (strcmp (image->config->env[1], "FOO=docker_is_a_really"))
    exit (5);
  if (strcmp (image->config->entrypoint[0], "/bin/sh"))
    exit (5);
  if (image->config->volumes_len != 2)
    exit (5);
  if (strcmp (image->config->volumes[0], "/var/job-result-data"))
    exit (5);
  if (strcmp (image->config->volumes[1], "/var/log/my-app-logs"))
    exit (5);
  result = oci_image_generate_json(image, 0, &err);
  if (result) {
    printf("res:%s\n", result);
  } else {
    printf("error %s\n", err);
    exit (1);
  }

  free(result);
  free_oci_image (image);
  exit (0);
}
