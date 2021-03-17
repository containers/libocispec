libocispec
==========

[![Build Status](https://travis-ci.org/containers/libocispec.svg?branch=master)](https://travis-ci.org/containers/libocispec)

A library for easily parsing
of [OCI runtime](https://github.com/opencontainers/runtime-spec)
and [OCI image](https://github.com/opencontainers/image-spec) files
from C, and generate json string from corresponding struct.

The parser is generated directly from the JSON schema in the source repository.

## Installation
Expects [yajl](https://github.com/containers/yajl) to be installed and linkable.
```sh
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

Parsing an OCI configuration file is easy as:

```c
    runtime_spec_schema_config_schema *container = runtime_spec_schema_config_schema_parse_file ("config.json", NULL, &err);

    if (container == NULL)
      exit (EXIT_FAILURE);

    /* Print the container hostname.  */
    if (container->hostname)
        printf ("The specified hostname is %s\n", container->hostname);

    for (size_t i; i < container->mounts_len; i++)
        printf ("Mounting to %s\n", container->mounts[i]->destination);

    printf ("Running as user ID and GID %d %d\n", container->process->user->uid, container->process->user->gid);

```

Generating an OCI configuration json string is also easy as:

```c
    runtime_spec_schema_config_schema container;
    char *json_buf = NULL;

    memset (&container, 0, sizeof (runtime_spec_schema_config_schema));

    container.oci_version = "2";
    container.hostname = "ubuntu";
    /* Add other configuration. */
    /* ... ... */

    json_buf = runtime_spec_schema_config_schema_generate_json (&container, NULL, &err);
    if (json_buf == NULL)
      exit (EXIT_FAILURE);

    printf ("The generated json string is:\n%s\n", json_buf);

```
