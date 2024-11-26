#ifndef _JSON_COMMON_H
#define _JSON_COMMON_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

#undef linux

#ifdef __MUSL__
#undef stdin
#undef stdout
#undef stderr
#define stdin stdin
#define stdout stdout
#define stderr stderr
#endif

// options to report error if there is unknown key found in json
#define OPT_PARSE_STRICT 0x01
// options to generate all key and value
#define OPT_GEN_KEY_VALUE 0x02
// options to generate simplify(no indent) json string
#define OPT_GEN_SIMPLIFY 0x04
// options to keep all keys and values, even do not known
#define OPT_PARSE_FULLKEY 0x08
// options not to validate utf8 data
#define OPT_GEN_NO_VALIDATE_UTF8 0x10

// Generating json succeded
#define JSON_GEN_SUCCESS 0

// Generating json failed
#define JSON_GEN_FAILED -1

#define define_cleaner_function(type, cleaner)      \
  static inline void cleaner##_function (type *ptr) \
  {                                                 \
    if (*ptr)                                       \
      cleaner (*ptr);                               \
  }

#define __auto_cleanup(cleaner) __attribute__ ((__cleanup__ (cleaner##_function)))

static inline void
ptr_free_function (void *p)
{
  free (*(void **) p);
}

#define __auto_free __auto_cleanup (ptr_free)

#define move_ptr(ptr)               \
  ({                                \
    typeof (ptr) moved_ptr = (ptr); \
    (ptr) = NULL;                   \
    moved_ptr;                      \
  })

#define GEN_SET_ERROR_AND_RETURN(stat, err)                                                                           \
  {                                                                                                                   \
    if (*(err) == NULL)                                                                                               \
      {                                                                                                               \
        if (asprintf (err, "%s: %s: %d: error generating json, errcode: %u", __FILE__, __func__, __LINE__, stat) < 0) \
          {                                                                                                           \
            *(err) = strdup ("error allocating memory");                                                              \
          }                                                                                                           \
      }                                                                                                               \
    return stat;                                                                                                      \
  }

typedef char *parser_error;

struct parser_context
{
  unsigned int options;
  FILE *errfile;
};

char *safe_strdup (const char *src);

void *safe_malloc (size_t size);

int json_double_to_int (double d, int *converted);

int json_double_to_int64 (double d, int64_t *converted);

int json_double_to_int32 (double d, int32_t *converted);

int json_double_to_int16 (double d, int16_t *converted);

int json_double_to_int8 (double d, int8_t *converted);

int json_double_to_uint (double d, unsigned int *converted);

int json_double_to_uint64 (double d, uint64_t *converted);

int json_double_to_uint32 (double d, uint32_t *converted);

int json_double_to_uint16 (double d, uint16_t *converted);

int json_double_to_uint8 (double d, uint8_t *converted);

int json_double_to_double (double d, double *converted);

typedef struct
{
  int *keys;
  int *values;
  size_t len;
} json_map_int_int;

void free_json_map_int_int (json_map_int_int *map);

int gen_json_map_int_int (json_t *root, const json_map_int_int *map, 
                                      parser_error *err);

int append_json_map_int_int (json_map_int_int *map, int key, int val);

typedef struct
{
  int *keys;
  bool *values;
  size_t len;
} json_map_int_bool;

void free_json_map_int_bool (json_map_int_bool *map);

int gen_json_map_int_bool (json_t *root, const json_map_int_bool *map, 
                                       parser_error *err);

int append_json_map_int_bool (json_map_int_bool *map, int key, bool val);

typedef struct
{
  int *keys;
  char **values;
  size_t len;
} json_map_int_string;

void free_json_map_int_string (json_map_int_string *map);

int gen_json_map_int_string (json_t *root, const json_map_int_string *map, 
                                         parser_error *err);

int append_json_map_int_string (json_map_int_string *map, int key, const char *val);

typedef struct
{
  char **keys;
  int *values;
  size_t len;
} json_map_string_int;

void free_json_map_string_int (json_map_string_int *map);

int gen_json_map_string_int (json_t *root, const json_map_string_int *map, 
                                         parser_error *err);

int append_json_map_string_int (json_map_string_int *map, const char *key, int val);

typedef struct
{
  char **keys;
  bool *values;
  size_t len;
} json_map_string_bool;

void free_json_map_string_bool (json_map_string_bool *map);

typedef struct
{
  char **keys;
  int64_t *values;
  size_t len;
} json_map_string_int64;

void free_json_map_string_int64 (json_map_string_int64 *map);

int gen_json_map_string_int64 (json_t *root, const json_map_string_int64 *map,
                                            parser_error *err);

int append_json_map_string_int64 (json_map_string_int64 *map, const char *key, int64_t val);

int gen_json_map_string_bool (json_t *root, const json_map_string_bool *map, 
                                          parser_error *err);

int append_json_map_string_bool (json_map_string_bool *map, const char *key, bool val);

typedef struct
{
  char **keys;
  char **values;
  size_t len;
} json_map_string_string;

void free_json_map_string_string (json_map_string_string *map);

json_map_string_string *clone_map_string_string (json_map_string_string *src);

json_map_string_string *make_json_map_string_string (json_t *src, const struct parser_context *ctx, parser_error *err);

int gen_json_map_string_string (json_t *root, const json_map_string_string *map, parser_error *err);

int append_json_map_string_string (json_map_string_string *map, const char *key, const char *val);

char *json_marshal_string (const char *str, size_t length, const struct parser_context *ctx, parser_error *err);

typedef struct
{
  json_t * values;
  size_t len;
} jansson_array_values;

jansson_array_values *json_array_to_struct(json_t *array);

typedef struct
{
  const char **keys; 
  json_t * values;
  size_t len;
} jansson_object_keys_values;

jansson_object_keys_values *json_object_to_keys_values(json_t *object);

json_t *copy_unmatched_fields(json_t *src, const char **exclude_keys, size_t num_keys);

#ifdef __cplusplus
}
#endif

#endif