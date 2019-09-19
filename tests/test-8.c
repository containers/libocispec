/* Copyright (C) 2017 YiFeng Tan <tanyifeng1@huawei.com>

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
#include <image_manifest_items.h>

int
main ()
{
  parser_error err = NULL;
  size_t len, len_gen;
  image_manifest_items_element **image_items = image_manifest_items_parse_file ("tests/data/image_manifest_item.json", 0, &err, &len);
  image_manifest_items_element **image_items_gen = NULL;
  char *json_buf = NULL;

  if (image_items == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = image_manifest_items_generate_json (image_items, len, 0, &err);
  if (json_buf == NULL) {
    printf ("gen error %s\n", err);
    exit (1);
  }

  image_items_gen = image_manifest_items_parse_data (json_buf, 0, &err, &len_gen);
  if (image_items_gen == NULL) {
    printf ("parse error %s\n", err);
    exit (1);
  }

  if (len != 1 || len != len_gen)
    exit (5);
  if (!image_items[0]->config || strcmp (image_items[0]->config, image_items_gen[0]->config) || \
      strcmp (image_items_gen[0]->config, "5b117edd0b767986092e9f721ba2364951b0a271f53f1f41aff9dd1861c2d4fe.json"))
    exit (6);
  if (image_items[0]->layers_len != 5 || image_items[0]->layers_len != image_items_gen[0]->layers_len || \
      strcmp (image_items[0]->layers[2], image_items_gen[0]->layers[2]) || \
      strcmp (image_items_gen[0]->layers[2], "e5ffeddba503ff2220cf4587030131c2cee5aef6083df1d2559e3d576bf04c99/layer.tar"))
    exit (7);
  if (image_items[0]->repo_tags_len != 0 || image_items[0]->repo_tags_len != image_items_gen[0]->repo_tags_len || image_items[0]->repo_tags != NULL)
    exit (8);

  free (json_buf);
  free_image_manifest_items (image_items, len);
  free_image_manifest_items (image_items_gen, len_gen);
  exit (0);
}
