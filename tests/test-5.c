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
#include "oci_image_layout_spec.h"

int
main (int argc, char *argv[])
{
  oci_parser_error err;
  oci_image_layout *image_layout = oci_image_layout_parse_file ("tests/data/image_layout_config.json", 0, &err);

  if (image_layout == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  if (strcmp (image_layout->image_layout_version, "1.0.0"))
    exit (5);

  free_oci_image_layout (image_layout);
  exit (0);
}
