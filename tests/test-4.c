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
#include "oci_image_index_spec.h"

int
main (int argc, char *argv[])
{
  oci_parser_error err;
  oci_image_index *image_index = oci_image_index_parse_file ("tests/image_index_config.json", 0, &err);

  if (image_index == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  if (image_index->schemaVersion != 2)
    exit (5);
  if (image_index->annotations->len != 2)
    exit (5);
  if (image_index->annotations->len != 2)
    exit (5);
  if (strcmp (image_index->annotations->keys[0], "com.example.key1"))
    exit (5);
  if (strcmp (image_index->annotations->values[1], "value2"))
    exit (5);
  if (strcmp (image_index->manifests[0]->mediaType, "application/vnd.oci.image.manifest.v1+json"))
    exit (5);
  if (image_index->manifests[0]->size != 7143)
    exit (5);
  if (strcmp (image_index->manifests[0]->digest, "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f"))
    exit (5);
  if (strcmp (image_index->manifests[0]->platform->os, "linux"))
    exit (5);
  if (strcmp (image_index->manifests[0]->platform->os_version, "1.0.0"))
    exit (5);
  if (image_index->manifests[0]->platform->os_features_len != 2)
    exit (5);
  if (strcmp (image_index->manifests[0]->platform->os_features[1], "simple"))
    exit (5);
  if (strcmp (image_index->manifests[0]->platform->architecture, "ppc64le"))
    exit (5);

  free_oci_image_index (image_index);
  exit (0);
}
