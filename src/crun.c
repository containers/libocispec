/* Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>

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
#include <sys/types.h>
#include <sys/wait.h>

int
main (int argc, char *argv[])
{
  JsonNode *rootval;
  JsonObject *root;
  GError *gerror = NULL;
  struct context *context;
  char **bwrap_argv = NULL;
  JsonParser *parser;
  GOptionContext *opt_context;
  int block_fd[2];
  int info_fd[2];
  int sync_fd[2];
  return EXIT_FAILURE;
}
