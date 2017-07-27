libocispec
==========

[![Build Status](https://travis-ci.org/giuseppe/libocispec.svg?branch=master)](https://travis-ci.org/giuseppe/libocispec)

A library for easily parsing
of [OCI runtime](https://github.com/opencontainers/runtime-spec)
and [OCI image](https://github.com/opencontainers/image-spec) files
from C.

The parser is generated directly from the JSON schema in the source repository.

Parsing an OCI configuration file is easy as:

```c
    oci_container_container *container = oci_parse_file ("config.json", NULL, &err);

    if (container == NULL)
      exit (EXIT_FAILURE);

    /* Print the container hostname.  */
    if (container->hostname)
        printf ("The specified hostname is %s\n", container->hostname);

    for (size_t i; i < container->mounts_len; i++)
        printf ("Mounting to %s\n", container->mounts[i]->destination);

    printf ("Running as user ID and GID %d %d\n", container->process->uid, container->process->gid);

```
