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
  oci_image *image = oci_image_parse_file ("tests/data/image_config_mapstringobject.json", 0, &err);
  oci_image *image_gen = NULL;
  char *json_buf = NULL;

  if (image == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = oci_image_generate_json(image, 0, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    exit (1);
  }
  image_gen = oci_image_parse_data(json_buf, 0, &err);
  if (image_gen == NULL) {
    printf("parse error %s\n", err);
    exit(1);
  }

  if (image->config->volumes_len != 0 || image_gen->config->volumes_len != 0)
    exit (5);
  if (image->config->volumes != NULL || image_gen->config->volumes != NULL)
    exit (5);
  if (image->config->exposed_ports_len != 1 || image_gen->config->exposed_ports_len != 1)
    exit (5);
  if (strcmp (image->config->exposed_ports[0], "8080/tcp") && strcmp (image->config->exposed_ports[0], image_gen->config->exposed_ports[0]))
    exit (5);

  free(json_buf);
  free_oci_image (image);
  free_oci_image (image_gen);
  exit (0);
}
