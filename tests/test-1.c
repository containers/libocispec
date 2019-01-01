/* Copyright (C) 2017, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>

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
#include <oci_runtime_spec.h>

int
main (int argc, char *argv[])
{
  parser_error err;
  oci_container *container = oci_container_parse_file ("tests/data/config.json", 0, &err);
  oci_container *container_gen = NULL;
  char *json_buf = NULL;

  if (container == NULL) {
    printf ("error %s\n", err);
    exit (1);
  }
  json_buf = oci_container_generate_json(container, 0, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    exit (1);
  }
  container_gen = oci_container_parse_data(json_buf, 0, &err);
  if (container == NULL) {
    printf ("parse error %s\n", err);
    exit (1);
  }

  if (strcmp (container->hostname, "runc") && strcmp(container->hostname, container_gen->hostname))
    exit (5);
  if (strcmp (container->process->cwd, "/cwd") && strcmp (container->process->cwd, container_gen->process->cwd))
    exit (5);
  if (container->process->user->uid != 101 || container_gen->process->user->uid != 101)
    exit (5);
  if (strcmp (container->process->args[0], "ARGS1") && strcmp (container->process->args[0], container_gen->process->args[0]))
    exit (5);
  if (strcmp (container->mounts[0]->destination, "/proc") && strcmp (container->mounts[0]->destination, container_gen->mounts[0]->destination))
    exit (5);
  if (container->linux->resources->block_io->weight_device[0]->major != 8 || container_gen->linux->resources->block_io->weight_device[0]->major != 8)
    exit (5);
  if (container->linux->resources->block_io->weight_device[0]->minor != 0 || container_gen->linux->resources->block_io->weight_device[0]->minor != 0)
    exit (5);
  if (container->linux->resources->block_io->weight_device[0]->weight != 500 || container_gen->linux->resources->block_io->weight_device[0]->weight != 500)
    exit (5);
  if (container->linux->resources->block_io->weight_device[0]->leaf_weight != 300 || container_gen->linux->resources->block_io->weight_device[0]->leaf_weight != 300)
    exit (5);
  if (container->linux->resources->block_io->throttle_read_bps_device[0]->major != 8 || container_gen->linux->resources->block_io->throttle_read_bps_device[0]->major != 8)
    exit (5);
  if (container->linux->resources->block_io->throttle_read_bps_device[0]->minor != 0 || container_gen->linux->resources->block_io->throttle_read_bps_device[0]->minor != 0)
    exit (5);
  if (container->linux->resources->block_io->throttle_read_bps_device[0]->rate != 600 || container_gen->linux->resources->block_io->throttle_read_bps_device[0]->rate != 600)
    exit (5);
  if (container->linux->resources->block_io->throttle_write_iops_device[0]->major != 8 || container_gen->linux->resources->block_io->throttle_write_iops_device[0]->major != 8)
    exit (5);
  if (container->linux->resources->block_io->throttle_write_iops_device[0]->minor != 16 || container_gen->linux->resources->block_io->throttle_write_iops_device[0]->minor != 16)
    exit (5);
  if (container->linux->resources->block_io->throttle_write_iops_device[0]->rate != 300 || container_gen->linux->resources->block_io->throttle_write_iops_device[0]->rate != 300)
    exit (5);
  if (container->linux->namespaces_len != 5 || container_gen->linux->namespaces_len != 5)
    exit (5);
  if (strcmp(container->linux->namespaces[2]->type, "ipc") && strcmp(container->linux->namespaces[2]->type, container_gen->linux->namespaces[2]->type))
    exit (5);

  free(json_buf);
  free_oci_container (container);
  free_oci_container (container_gen);
  exit (0);
}
