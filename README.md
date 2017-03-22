libocispec
==========

A library for easily parsing
of [OCI](https://github.com/opencontainers/runtime-spec) runtime spec
files from C.

The parser is generated directly from the JSON schema in the
runtime-spec source repository.

Parsing an OCI configuration file is easy as:

```c
    oci_container_container *container = oci_parse_file ("config.json", &err);

    if (container == NULL)
      exit (1);

    /* Print the container hostname.  */
    if (container->hostname)
        printf ("The specified hostname is %s\n", container->hostname);

    for (size_t i; i < container->mounts_len; i++)
        printf ("Mounting to %s\n", container->mounts[i]->destination);

    printf ("Running as user ID and GID %d %d\n", container->process->uid, container->process->gid);

```
