/* Copyright (C) 2021 duguhaotian <knowledgehao@163.com>

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
#include "ocispec/image_spec_schema_image_layout_schema.h"

#ifndef OPT_PARSE_FULLKEY
# define OPT_PARSE_FULLKEY 0x08
#endif

int
main ()
{
  parser_error err;
  struct parser_context ctx;
  ctx.options = OPT_PARSE_FULLKEY;

  image_spec_schema_image_layout_schema *image_layout = image_spec_schema_image_layout_schema_parse_file ("tests/data/null_value_config.json", &ctx, &err);
  image_spec_schema_image_layout_schema *image_layout_gen = NULL;
  char *json_buf = NULL;

  if (image_layout == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = image_spec_schema_image_layout_schema_generate_json(image_layout, &ctx, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    free(err);
    exit (1);
  }
  image_layout_gen = image_spec_schema_image_layout_schema_parse_data(json_buf, 0, &err);
  if (image_layout_gen == NULL) {
    printf("parse error %s\n", err);
    free(err);
    exit(1);
  }

  if (strcmp (image_layout->image_layout_version, "1.0.0") && strcmp (image_layout->image_layout_version, image_layout_gen->image_layout_version))
    exit (5);

  printf("%s\n", json_buf);

  // origin json str should same with generate new json str,
  if (strstr(json_buf, "just-key\": null") == NULL)
    exit (51);
  if (strstr(json_buf, "key1\": null") == NULL)
    exit (52);

  free(json_buf);
  free_image_spec_schema_image_layout_schema (image_layout);
  free_image_spec_schema_image_layout_schema (image_layout_gen);
  exit (0);
}
