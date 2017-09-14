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
#include <oci_image_layout_spec.h>

int
main (int argc, char *argv[])
{
  parser_error err;
  oci_image_layout *image_layout = oci_image_layout_parse_file ("tests/data/image_layout_config.json", 0, &err);
  oci_image_layout *image_layout_gen = NULL;
  char *json_buf = NULL;

  if (image_layout == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = oci_image_layout_generate_json(image_layout, 0, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    exit (1);
  }
  image_layout_gen = oci_image_layout_parse_data(json_buf, 0, &err);
  if (image_layout_gen == NULL) {
    printf("parse error %s\n", err);
    exit(1);
  }

  if (strcmp (image_layout->image_layout_version, "1.0.0") && strcmp (image_layout->image_layout_version, image_layout_gen->image_layout_version))
    exit (5);

  free(json_buf);
  free_oci_image_layout (image_layout);
  free_oci_image_layout (image_layout_gen);
  exit (0);
}
