/* Copyright (C) 2020 duguhaotian <knowledgehao@163.com>

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

  image_spec_schema_image_layout_schema *image_layout = image_spec_schema_image_layout_schema_parse_file ("tests/data/residual_image_layout_config.json", &ctx, &err);
  image_spec_schema_image_layout_schema *image_layout_gen = NULL;
  char *json_buf = NULL;

  if (image_layout == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = image_spec_schema_image_layout_schema_generate_json(image_layout, &err);
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
  if (strstr(json_buf, "residual_int") == NULL)
    exit (51);
  if (strstr(json_buf, "residual_float") == NULL)
    exit (52);
  if (strstr(json_buf, "residual_string") == NULL)
    exit (53);
  if (strstr(json_buf, "residual_true") == NULL)
    exit (54);
  if (strstr(json_buf, "residual_false") == NULL)
    exit (55);
  if (strstr(json_buf, "residual_array") == NULL)
    exit (56);
  if (strstr(json_buf, "residual_obj") == NULL)
    exit (57);
  if (strstr(json_buf, "key1") == NULL ||
          strstr(json_buf, "key2") == NULL ||
          strstr(json_buf, "key3") == NULL)
    exit (58);
  if (strstr(json_buf, "value1") == NULL ||
          strstr(json_buf, "value2") == NULL ||
          strstr(json_buf, "value3") == NULL)
    exit (59);

  free(json_buf);
  free_image_spec_schema_image_layout_schema (image_layout);
  free_image_spec_schema_image_layout_schema (image_layout_gen);
  exit (0);
}
