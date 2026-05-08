#ifndef _JSON_COMMON_H
#define _JSON_COMMON_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

#undef linux

#ifdef __MUSL__
#  undef stdin
#  undef stdout
#  undef stderr
#  define stdin stdin
#  define stdout stdout
#  define stderr stderr
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
        if (asprintf (err, "%s: %s: %d: error generating json, errcode: %d", __FILE__, __func__, __LINE__, stat) < 0) \
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

/* Custom type sentinel for get_val() to match both json_type_int and json_type_double. */
#define json_c_type_number 100

/* Streaming JSON generator context -- wraps json-c object building. */
#define JSON_GEN_MAX_DEPTH 64

typedef int json_gen_status;
#define json_gen_status_ok 0
#define json_gen_in_error_state (-1)

/* Beautify config constant (used with json_gen_config). */
#define json_gen_beautify 0

typedef struct
{
  json_object *stack[JSON_GEN_MAX_DEPTH];
  char *pending_key[JSON_GEN_MAX_DEPTH];
  bool is_map[JSON_GEN_MAX_DEPTH];
  int depth;
  json_object *root;
  char *buf;
  size_t buf_len;
  bool beautify;
} json_gen_ctx;

json_gen_status json_gen_map_open (json_gen_ctx *g);
json_gen_status json_gen_map_close (json_gen_ctx *g);
json_gen_status json_gen_array_open (json_gen_ctx *g);
json_gen_status json_gen_array_close (json_gen_ctx *g);
json_gen_status json_gen_string (json_gen_ctx *g, const char *str, size_t len);
json_gen_status json_gen_number (json_gen_ctx *g, const char *numstr, size_t len);
json_gen_status json_gen_bool (json_gen_ctx *g, int val);
json_gen_status json_gen_double (json_gen_ctx *g, double val);
json_gen_status json_gen_null (json_gen_ctx *g);
json_gen_status json_gen_get_buf (json_gen_ctx *g, const char **buf, size_t *len);
void json_gen_config (json_gen_ctx *g, int option, int val);
void json_gen_free (json_gen_ctx *g);

json_gen_status gen_json_object_residual (json_object *residual, json_gen_ctx *g, parser_error *err);

json_gen_status map_uint (void *ctx, long long unsigned int num);

json_gen_status map_int (void *ctx, long long int num);

bool json_gen_init (json_gen_ctx **g, const struct parser_context *ctx);

json_object *get_val (json_object *tree, const char *name, int type);

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

typedef struct
{
  int *keys;
  int *values;
  size_t len;
} json_map_int_int;

void free_json_map_int_int (json_map_int_int *map);

json_map_int_int *make_json_map_int_int (json_object *src, const struct parser_context *ctx, parser_error *err);

json_gen_status gen_json_map_int_int (void *ctx, const json_map_int_int *map, const struct parser_context *ptx,
                                      parser_error *err);

int append_json_map_int_int (json_map_int_int *map, int key, int val);

typedef struct
{
  int *keys;
  bool *values;
  size_t len;
} json_map_int_bool;

void free_json_map_int_bool (json_map_int_bool *map);

json_map_int_bool *make_json_map_int_bool (json_object *src, const struct parser_context *ctx, parser_error *err);

json_gen_status gen_json_map_int_bool (void *ctx, const json_map_int_bool *map, const struct parser_context *ptx,
                                       parser_error *err);

int append_json_map_int_bool (json_map_int_bool *map, int key, bool val);

typedef struct
{
  int *keys;
  char **values;
  size_t len;
} json_map_int_string;

void free_json_map_int_string (json_map_int_string *map);

json_map_int_string *make_json_map_int_string (json_object *src, const struct parser_context *ctx, parser_error *err);

json_gen_status gen_json_map_int_string (void *ctx, const json_map_int_string *map, const struct parser_context *ptx,
                                         parser_error *err);

int append_json_map_int_string (json_map_int_string *map, int key, const char *val);

typedef struct
{
  char **keys;
  int *values;
  size_t len;
} json_map_string_int;

void free_json_map_string_int (json_map_string_int *map);

json_map_string_int *make_json_map_string_int (json_object *src, const struct parser_context *ctx, parser_error *err);

json_gen_status gen_json_map_string_int (void *ctx, const json_map_string_int *map, const struct parser_context *ptx,
                                         parser_error *err);

int append_json_map_string_int (json_map_string_int *map, const char *key, int val);

typedef struct
{
  char **keys;
  bool *values;
  size_t len;
} json_map_string_bool;

void free_json_map_string_bool (json_map_string_bool *map);

json_map_string_bool *make_json_map_string_bool (json_object *src, const struct parser_context *ctx, parser_error *err);

typedef struct
{
  char **keys;
  int64_t *values;
  size_t len;
} json_map_string_int64;

void free_json_map_string_int64 (json_map_string_int64 *map);

json_map_string_int64 *make_json_map_string_int64 (json_object *src, const struct parser_context *ctx, parser_error *err);

json_gen_status gen_json_map_string_int64 (void *ctx, const json_map_string_int64 *map,
                                           const struct parser_context *ptx, parser_error *err);

int append_json_map_string_int64 (json_map_string_int64 *map, const char *key, int64_t val);

json_gen_status gen_json_map_string_bool (void *ctx, const json_map_string_bool *map, const struct parser_context *ptx,
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

json_map_string_string *make_json_map_string_string (json_object *src, const struct parser_context *ctx, parser_error *err);

json_gen_status gen_json_map_string_string (void *ctx, const json_map_string_string *map,
                                            const struct parser_context *ptx, parser_error *err);

int append_json_map_string_string (json_map_string_string *map, const char *key, const char *val);

char *json_marshal_string (const char *str, size_t length, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif
