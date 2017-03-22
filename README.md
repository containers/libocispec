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
    if (container && container->hostname)
        printf ("The specified hostname is %s\n", container->hostname);
```
