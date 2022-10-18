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
#include "ocispec/image_spec_schema_config_schema.h"

int
main ()
{
  parser_error err;
  image_spec_schema_config_schema *image = image_spec_schema_config_schema_parse_file ("tests/data/image_config_mapstringobject.json", 0, &err);
  image_spec_schema_config_schema *image_gen = NULL;
  char *json_buf = NULL;

  if (image == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = image_spec_schema_config_schema_generate_json(image, 0, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    exit (1);
  }
  image_gen = image_spec_schema_config_schema_parse_data(json_buf, 0, &err);
  if (image_gen == NULL) {
    printf("parse error %s\n", err);
    exit(1);
  }

  if (image->config->volumes != NULL || image_gen->config->volumes != NULL)
    exit (5);
  if (image->config->exposed_ports->len != 1 || image_gen->config->exposed_ports->len != 1)
    exit (5);
  if (strcmp (image->config->exposed_ports->keys[0], "8080/tcp") && strcmp (image->config->exposed_ports->keys[0], image_gen->config->exposed_ports->keys[0]))
    exit (5);

  free(json_buf);
  free_image_spec_schema_config_schema (image);
  free_image_spec_schema_config_schema (image_gen);
  exit (0);
}
