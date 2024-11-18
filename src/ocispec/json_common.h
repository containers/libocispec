#ifndef _JSON_COMMON_H
#define _JSON_COMMON_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>
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

yajl_gen_status gen_yajl_object_residual (json_t *j, yajl_gen g, parser_error *err);

yajl_gen_status map_uint (void *ctx, long long unsigned int num);

yajl_gen_status map_int (void *ctx, long long int num);

bool json_gen_init (yajl_gen *g, const struct parser_context *ctx);

yajl_val get_val (yajl_val tree, const char *name, yajl_type type);

char *safe_strdup (const char *src);

void *safe_malloc (size_t size);

int common_safe_double (const char *numstr, double *converted);

int common_safe_uint8 (const char *numstr, uint8_t *converted);

int common_safe_uint16 (const char *numstr, uint16_t *converted);

int common_safe_uint32 (const char *numstr, uint32_t *converted);

int common_safe_uint64 (const char *numstr, uint64_t *converted);

int common_safe_uint (const char *numstr, unsigned int *converted);

int common_safe_int8 (const char *numstr, int8_t *converted);

int common_safe_int16 (const char *numstr, int16_t *converted);

int common_safe_int32 (const char *numstr, int32_t *converted);

int common_safe_int64 (const char *numstr, int64_t *converted);

int common_safe_int (const char *numstr, int *converted);

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

json_map_int_int *make_json_map_int_int (yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_int_int (void *ctx, const json_map_int_int *map, const struct parser_context *ptx,
                                      parser_error *err);

int append_json_map_int_int (json_map_int_int *map, int key, int val);

typedef struct
{
  int *keys;
  bool *values;
  size_t len;
} json_map_int_bool;

void free_json_map_int_bool (json_map_int_bool *map);

json_map_int_bool *make_json_map_int_bool (yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_int_bool (void *ctx, const json_map_int_bool *map, const struct parser_context *ptx,
                                       parser_error *err);

int append_json_map_int_bool (json_map_int_bool *map, int key, bool val);

typedef struct
{
  int *keys;
  char **values;
  size_t len;
} json_map_int_string;

void free_json_map_int_string (json_map_int_string *map);

json_map_int_string *make_json_map_int_string (yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_int_string (void *ctx, const json_map_int_string *map, const struct parser_context *ptx,
                                         parser_error *err);

int append_json_map_int_string (json_map_int_string *map, int key, const char *val);

typedef struct
{
  char **keys;
  int *values;
  size_t len;
} json_map_string_int;

void free_json_map_string_int (json_map_string_int *map);

json_map_string_int *make_json_map_string_int (yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_string_int (void *ctx, const json_map_string_int *map, const struct parser_context *ptx,
                                         parser_error *err);

int append_json_map_string_int (json_map_string_int *map, const char *key, int val);

typedef struct
{
  char **keys;
  bool *values;
  size_t len;
} json_map_string_bool;

void free_json_map_string_bool (json_map_string_bool *map);

json_map_string_bool *make_json_map_string_bool (yajl_val src, const struct parser_context *ctx, parser_error *err);

typedef struct
{
  char **keys;
  int64_t *values;
  size_t len;
} json_map_string_int64;

void free_json_map_string_int64 (json_map_string_int64 *map);

json_map_string_int64 *make_json_map_string_int64 (yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_string_int64 (void *ctx, const json_map_string_int64 *map,
                                           const struct parser_context *ptx, parser_error *err);

int append_json_map_string_int64 (json_map_string_int64 *map, const char *key, int64_t val);

yajl_gen_status gen_json_map_string_bool (void *ctx, const json_map_string_bool *map, const struct parser_context *ptx,
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

yajl_gen_status gen_json_map_string_string (void *ctx, const json_map_string_string *map,
                                            const struct parser_context *ptx, parser_error *err);

int append_json_map_string_string (json_map_string_string *map, const char *key, const char *val);

char *json_marshal_string (const char *str, size_t length, const struct parser_context *ctx, parser_error *err);

json_t *yajl_to_json(yajl_val val);

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

yajl_val json_to_yajl(json_t *json);

#ifdef __cplusplus
}
#endif

#endif