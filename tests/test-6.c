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
#include "oci_image_manifest_spec.h"

int
main (int argc, char *argv[])
{
  oci_parser_error err;
  oci_image_manifest_image_manifest *manifest = oci_image_manifest_parse_file ("tests/image_manifest.json", 0, &err);

  if (manifest == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  if (manifest->schemaVersion != 2)
    exit (5);
  if (strcmp (manifest->config->mediaType, "application/vnd.oci.image.config.v1+json"))
    exit (5);
  if (manifest->config->size != 1470)
    exit (5);
  if (manifest->layers_len != 3)
    exit (5);
  if (strcmp (manifest->layers[1]->digest, "sha256:2b689805fbd00b2db1df73fae47562faac1a626d5f61744bfe29946ecff5d73d"))
    exit (5);
  if (manifest->annotations->len != 2)
    exit (5);
  if (strcmp(manifest->annotations->keys[1], "key2"))
    exit (5);
  if (strcmp(manifest->annotations->values[1], "value2"))
    exit (5);
  free_oci_image_manifest_image_manifest (manifest);
  exit (0);
}
