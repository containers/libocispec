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
#include <oci_image_index_spec.h>

int
main (int argc, char *argv[])
{
  parser_error err;
  oci_image_index *image_index = oci_image_index_parse_file ("tests/data/image_index_config.json", 0, &err);
  oci_image_index *image_index_gen = NULL;
  char *json_buf = NULL;

  if (image_index == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = oci_image_index_generate_json(image_index, 0, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    exit (1);
  }
  image_index_gen = oci_image_index_parse_data(json_buf, 0, &err);
  if (image_index_gen == NULL) {
    printf("parse error %s\n", err);
    exit(1);
  }

  if (image_index->schema_version != 2 || image_index_gen->schema_version != 2)
    exit (5);
  if (image_index->annotations->len != 2 || image_index_gen->annotations->len != 2)
    exit (5);
  if (image_index->annotations->len != 2 || image_index_gen->annotations->len != 2)
    exit (5);
  if (strcmp (image_index->annotations->keys[0], "com.example.key1") && \
      strcmp (image_index->annotations->keys[0], image_index_gen->annotations->keys[0]))
    exit (5);
  if (strcmp (image_index->annotations->values[1], "value2") && \
      strcmp (image_index->annotations->values[1], image_index_gen->annotations->values[1]))
    exit (5);
  if (strcmp (image_index->manifests[0]->media_type, "application/vnd.oci.image.manifest.v1+json") && \
      strcmp (image_index->manifests[0]->media_type, image_index_gen->manifests[0]->media_type))
    exit (5);
  if (image_index->manifests[0]->size != 7143 || image_index_gen->manifests[0]->size != 7143)
    exit (5);
  if (strcmp (image_index->manifests[0]->digest, "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f") && \
      strcmp (image_index->manifests[0]->digest, image_index_gen->manifests[0]->digest))
    exit (5);
  if (strcmp (image_index->manifests[0]->platform->os, "linux") && \
      strcmp (image_index->manifests[0]->platform->os, image_index_gen->manifests[0]->platform->os))
    exit (5);
  if (strcmp (image_index->manifests[0]->platform->os_version, "1.0.0") && \
      strcmp (image_index->manifests[0]->platform->os_version, image_index_gen->manifests[0]->platform->os_version))
    exit (5);
  if (image_index->manifests[0]->platform->os_features_len != 2 || image_index_gen->manifests[0]->platform->os_features_len != 2)
    exit (5);
  if (strcmp (image_index->manifests[0]->platform->os_features[1], "simple") && \
      strcmp (image_index->manifests[0]->platform->os_features[1], image_index_gen->manifests[0]->platform->os_features[1]))
    exit (5);
  if (strcmp (image_index->manifests[0]->platform->architecture, "ppc64le") && \
      strcmp (image_index->manifests[0]->platform->architecture, image_index_gen->manifests[0]->platform->architecture))
    exit (5);

  free(json_buf);
  free_oci_image_index (image_index);
  free_oci_image_index (image_index_gen);
  exit (0);
}
