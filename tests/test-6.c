/* Copyright (C) 2017 Yifeng Tan <tanyifeng1@huawei.com>

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
#include "ocispec/image_spec_schema_image_manifest_schema.h"

int
main ()
{
  parser_error err;
  image_spec_schema_image_manifest_schema *manifest = image_spec_schema_image_manifest_schema_parse_file ("tests/data/image_manifest.json", 0, &err);
  image_spec_schema_image_manifest_schema *manifest_gen = NULL;
  char *json_buf = NULL;

  if (manifest == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = image_spec_schema_image_manifest_schema_generate_json(manifest, 0, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    exit (1);
  }
  manifest_gen = image_spec_schema_image_manifest_schema_parse_data(json_buf, 0, &err);
  if (manifest_gen == NULL) {
    printf("parse error %s\n", err);
    exit(1);
  }

  if (manifest->schema_version != 2 || manifest_gen->schema_version != 2)
    exit (5);
  if (strcmp (manifest->config->media_type, "application/vnd.oci.image.config.v1+json") && strcmp (manifest->config->media_type, manifest_gen->config->media_type))
    exit (5);
  if (manifest->config->size != 1470 || manifest_gen->config->size != 1470)
    exit (5);
  if (manifest->layers_len != 3 || manifest_gen->layers_len != 3)
    exit (5);
  if (strcmp (manifest->layers[1]->digest, "sha256:2b689805fbd00b2db1df73fae47562faac1a626d5f61744bfe29946ecff5d73d") || \
      strcmp (manifest->layers[1]->digest, manifest_gen->layers[1]->digest))
    exit (5);
  if (manifest->annotations->len != 2 || manifest_gen->annotations->len != 2)
    exit (5);
  if (strcmp(manifest->annotations->keys[1], "key2") && strcmp(manifest->annotations->keys[1], manifest_gen->annotations->keys[1]))
    exit (5);
  if (strcmp(manifest->annotations->values[1], "value2") && strcmp(manifest->annotations->values[1], manifest_gen->annotations->values[1]))
    exit (5);

  free(json_buf);
  free_image_spec_schema_image_manifest_schema (manifest);
  free_image_spec_schema_image_manifest_schema (manifest_gen);
  exit (0);
}
