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
  image_spec_schema_config_schema *image = image_spec_schema_config_schema_parse_file ("tests/data/image_config.json", 0, &err);
  image_spec_schema_config_schema *image_gen = NULL;
  char *json_buf = NULL;

  if (image == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = image_spec_schema_config_schema_generate_json(image, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    exit (1);
  }
  image_gen = image_spec_schema_config_schema_parse_data(json_buf, 0, &err);
  if (image_gen == NULL) {
    printf("parse error %s\n", err);
    exit(1);
  }

  if (strcmp (image->author, "Alyssa P. Hacker <alyspdev@example.com>") && strcmp (image->author, image_gen->author))
    exit (5);
  if (strcmp (image->created, "2015-10-31T22:22:56.015925234Z") && strcmp (image->created, image_gen->created))
    exit (5);
  if (strcmp (image->os, "linux") && strcmp (image->os, image_gen->os))
    exit (5);
  if (strcmp (image->architecture, "amd64") && strcmp (image->architecture, image_gen->architecture))
    exit (5);
  if (strcmp (image->config->user, "1:1") && strcmp (image->config->user, image_gen->config->user))
    exit (5);
  if (strcmp (image->config->env[1], "FOO=docker_is_a_really") && strcmp (image->config->env[1], image_gen->config->env[1]))
    exit (5);
  if (strcmp (image->config->entrypoint[0], "/bin/sh") && strcmp (image->config->entrypoint[0], image_gen->config->entrypoint[0]))
    exit (5);
  if (image->config->volumes->len != 2 || image_gen->config->volumes->len != 2)
    exit (5);
  if (strcmp (image->config->volumes->keys[0], "/var/job-result-data") && strcmp (image->config->volumes->keys[0], image_gen->config->volumes->keys[0]))
    exit (5);
  if (strcmp (image->config->volumes->keys[1], "/var/log/my-app-logs") && strcmp (image->config->volumes->keys[1], image_gen->config->volumes->keys[1]))
    exit (5);
  free(json_buf);
  free_image_spec_schema_config_schema (image);
  free_image_spec_schema_config_schema(image_gen);
  exit (0);
}
