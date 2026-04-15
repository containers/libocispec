#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "ocispec/json_common.h"

#define MAX_NUM_STR_LEN 21

/* ---------------------------------------------------------------------------
 * Streaming JSON generator -- wraps yyjson_mut_doc
 * ---------------------------------------------------------------------------*/

static json_gen_status
add_value (json_gen_ctx *g, yyjson_mut_val *val)
{
  if (val == NULL)
    return json_gen_in_error_state;

  if (g->depth < 0)
    {
      /* Top-level value (no container open yet). */
      g->root = val;
      return json_gen_status_ok;
    }

  if (g->is_map[g->depth])
    {
      if (g->keys[g->depth] != NULL)
        {
          /* We have a pending key — add key:value pair. */
          yyjson_mut_obj_add (g->stack[g->depth], g->keys[g->depth], val);
          g->keys[g->depth] = NULL;
        }
      else
        {
          /* No pending key in a map — this shouldn't happen. */
          return json_gen_in_error_state;
        }
    }
  else
    {
      /* We're in an array — append. */
      yyjson_mut_arr_append (g->stack[g->depth], val);
    }

  return json_gen_status_ok;
}

json_gen_status
json_gen_map_open (json_gen_ctx *g)
{
  yyjson_mut_val *obj;

  if (g->depth + 1 >= JSON_GEN_MAX_DEPTH)
    return json_gen_in_error_state;

  obj = yyjson_mut_obj (g->doc);
  if (obj == NULL)
    return json_gen_in_error_state;

  g->depth++;
  g->stack[g->depth] = obj;
  g->is_map[g->depth] = true;
  g->keys[g->depth] = NULL;

  return json_gen_status_ok;
}

json_gen_status
json_gen_map_close (json_gen_ctx *g)
{
  yyjson_mut_val *obj;

  if (g->depth < 0)
    return json_gen_in_error_state;

  obj = g->stack[g->depth];
  g->depth--;

  return add_value (g, obj);
}

json_gen_status
json_gen_array_open (json_gen_ctx *g)
{
  yyjson_mut_val *arr;

  if (g->depth + 1 >= JSON_GEN_MAX_DEPTH)
    return json_gen_in_error_state;

  arr = yyjson_mut_arr (g->doc);
  if (arr == NULL)
    return json_gen_in_error_state;

  g->depth++;
  g->stack[g->depth] = arr;
  g->is_map[g->depth] = false;
  g->keys[g->depth] = NULL;

  return json_gen_status_ok;
}

json_gen_status
json_gen_array_close (json_gen_ctx *g)
{
  yyjson_mut_val *arr;

  if (g->depth < 0)
    return json_gen_in_error_state;

  arr = g->stack[g->depth];
  g->depth--;

  return add_value (g, arr);
}

json_gen_status
json_gen_string (json_gen_ctx *g, const char *str, size_t len)
{
  yyjson_mut_val *val;

  if (g->depth >= 0 && g->is_map[g->depth] && g->keys[g->depth] == NULL)
    {
      /* In a map without a pending key — this string is the key. */
      g->keys[g->depth] = yyjson_mut_strncpy (g->doc, str, len);
      if (g->keys[g->depth] == NULL)
        return json_gen_in_error_state;
      return json_gen_status_ok;
    }

  val = yyjson_mut_strncpy (g->doc, str, len);
  return add_value (g, val);
}

json_gen_status
json_gen_number (json_gen_ctx *g, const char *numstr, size_t len)
{
  yyjson_mut_val *val = yyjson_mut_rawncpy (g->doc, numstr, len);
  return add_value (g, val);
}

json_gen_status
json_gen_bool (json_gen_ctx *g, int val)
{
  yyjson_mut_val *v = yyjson_mut_bool (g->doc, val);
  return add_value (g, v);
}

json_gen_status
json_gen_double (json_gen_ctx *g, double val)
{
  yyjson_mut_val *v = yyjson_mut_real (g->doc, val);
  return add_value (g, v);
}

json_gen_status
json_gen_null (json_gen_ctx *g)
{
  yyjson_mut_val *v = yyjson_mut_null (g->doc);
  return add_value (g, v);
}

json_gen_status
json_gen_get_buf (json_gen_ctx *g, const char **buf, size_t *len)
{
  yyjson_write_flag flags = 0;

  /* Free previous buffer if any. */
  if (g->buf != NULL)
    {
      free (g->buf);
      g->buf = NULL;
    }

  if (g->beautify)
    flags |= YYJSON_WRITE_PRETTY;

  if (g->root == NULL)
    return json_gen_in_error_state;

  yyjson_mut_doc_set_root (g->doc, g->root);
  g->buf = yyjson_mut_write (g->doc, flags, &g->buf_len);
  if (g->buf == NULL)
    return json_gen_in_error_state;

  /* Strip trailing newline if present. */
  if (g->buf_len > 0 && g->buf[g->buf_len - 1] == '\n')
    {
      g->buf_len--;
      g->buf[g->buf_len] = '\0';
    }

  *buf = g->buf;
  *len = g->buf_len;
  return json_gen_status_ok;
}

void
json_gen_config (json_gen_ctx *g, int option, int val)
{
  if (g == NULL)
    return;
  if (option == json_gen_beautify)
    g->beautify = (val != 0);
}

void
json_gen_free (json_gen_ctx *g)
{
  if (g == NULL)
    return;
  if (g->buf != NULL)
    free (g->buf);
  if (g->doc != NULL)
    yyjson_mut_doc_free (g->doc);
  free (g);
}

/* ---------------------------------------------------------------------------
 * Residual generation -- parse stored JSON string, inject into gen context
 * ---------------------------------------------------------------------------*/

static json_gen_status
gen_json_val (yyjson_val *val, json_gen_ctx *g, parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  yyjson_type type = yyjson_get_type (val);

  switch (type)
    {
    case YYJSON_TYPE_STR:
      {
        const char *str = yyjson_get_str (val);
        if (str == NULL)
          return stat;
        stat = json_gen_string (g, str, strlen (str));
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    case YYJSON_TYPE_NUM:
      {
        char numstr[MAX_NUM_STR_LEN];
        int nret;
        yyjson_subtype subtype = yyjson_get_subtype (val);
        if (subtype == YYJSON_SUBTYPE_UINT)
          nret = snprintf (numstr, sizeof (numstr), "%llu", (unsigned long long) yyjson_get_uint (val));
        else if (subtype == YYJSON_SUBTYPE_SINT)
          nret = snprintf (numstr, sizeof (numstr), "%lld", (long long) yyjson_get_sint (val));
        else
          nret = snprintf (numstr, sizeof (numstr), "%g", yyjson_get_real (val));
        if (nret < 0 || (size_t) nret >= sizeof (numstr))
          return json_gen_in_error_state;
        stat = json_gen_number (g, numstr, strlen (numstr));
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    case YYJSON_TYPE_RAW:
      {
        const char *raw = yyjson_get_raw (val);
        if (raw == NULL)
          return stat;
        stat = json_gen_number (g, raw, strlen (raw));
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    case YYJSON_TYPE_BOOL:
      stat = json_gen_bool (g, yyjson_get_bool (val));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      return json_gen_status_ok;
    case YYJSON_TYPE_NULL:
      stat = json_gen_null (g);
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      return json_gen_status_ok;
    case YYJSON_TYPE_OBJ:
      {
        yyjson_obj_iter iter;
        yyjson_val *key;
        stat = json_gen_map_open (g);
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        yyjson_obj_iter_init (val, &iter);
        while ((key = yyjson_obj_iter_next (&iter)) != NULL)
          {
            yyjson_val *v = yyjson_obj_iter_get_val (key);
            const char *kstr = yyjson_get_str (key);
            stat = json_gen_string (g, kstr, strlen (kstr));
            if (json_gen_status_ok != stat)
              GEN_SET_ERROR_AND_RETURN (stat, err);
            stat = gen_json_val (v, g, err);
            if (json_gen_status_ok != stat)
              GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = json_gen_map_close (g);
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    case YYJSON_TYPE_ARR:
      {
        yyjson_arr_iter iter;
        yyjson_val *v;
        stat = json_gen_array_open (g);
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        yyjson_arr_iter_init (val, &iter);
        while ((v = yyjson_arr_iter_next (&iter)) != NULL)
          {
            stat = gen_json_val (v, g, err);
            if (json_gen_status_ok != stat)
              GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = json_gen_array_close (g);
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    default:
      return stat;
    }
}

json_gen_status
gen_json_object_residual (const char *residual, json_gen_ctx *g, parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  yyjson_doc *doc;
  yyjson_val *root;
  yyjson_obj_iter iter;
  yyjson_val *key;

  if (residual == NULL)
    return json_gen_status_ok;

  doc = yyjson_read (residual, strlen (residual), YYJSON_READ_NUMBER_AS_RAW);
  if (doc == NULL)
    return json_gen_in_error_state;

  root = yyjson_doc_get_root (doc);
  if (root == NULL || ! yyjson_is_obj (root))
    {
      yyjson_doc_free (doc);
      return json_gen_in_error_state;
    }

  yyjson_obj_iter_init (root, &iter);
  while ((key = yyjson_obj_iter_next (&iter)) != NULL)
    {
      yyjson_val *v = yyjson_obj_iter_get_val (key);
      const char *kstr = yyjson_get_str (key);

      stat = json_gen_string (g, kstr, strlen (kstr));
      if (json_gen_status_ok != stat)
        {
          yyjson_doc_free (doc);
          GEN_SET_ERROR_AND_RETURN (stat, err);
        }
      stat = gen_json_val (v, g, err);
      if (json_gen_status_ok != stat)
        {
          yyjson_doc_free (doc);
          GEN_SET_ERROR_AND_RETURN (stat, err);
        }
    }

  yyjson_doc_free (doc);
  return json_gen_status_ok;
}

/* ---------------------------------------------------------------------------
 * map_uint / map_int -- write a number to the generator
 * ---------------------------------------------------------------------------*/

json_gen_status
map_uint (void *ctx, long long unsigned int num)
{
  char numstr[MAX_NUM_STR_LEN];
  int ret;

  ret = snprintf (numstr, sizeof (numstr), "%llu", num);
  if (ret < 0 || (size_t) ret >= sizeof (numstr))
    return json_gen_in_error_state;
  return json_gen_number ((json_gen_ctx *) ctx, (const char *) numstr, strlen (numstr));
}

json_gen_status
map_int (void *ctx, long long int num)
{
  char numstr[MAX_NUM_STR_LEN];
  int ret;

  ret = snprintf (numstr, sizeof (numstr), "%lld", num);
  if (ret < 0 || (size_t) ret >= sizeof (numstr))
    return json_gen_in_error_state;
  return json_gen_number ((json_gen_ctx *) ctx, (const char *) numstr, strlen (numstr));
}

/* ---------------------------------------------------------------------------
 * json_gen_init -- allocate and configure generator context
 * ---------------------------------------------------------------------------*/

bool
json_gen_init (json_gen_ctx **g, const struct parser_context *ctx)
{
  json_gen_ctx *gen = calloc (1, sizeof (json_gen_ctx));
  if (gen == NULL)
    return false;

  gen->doc = yyjson_mut_doc_new (NULL);
  if (gen->doc == NULL)
    {
      free (gen);
      return false;
    }

  gen->depth = -1;
  gen->root = NULL;
  gen->buf = NULL;
  gen->buf_len = 0;
  gen->beautify = (ctx == NULL) || ! (ctx->options & OPT_GEN_SIMPLIFY);

  *g = gen;
  return true;
}

/* ---------------------------------------------------------------------------
 * get_val -- look up a key in an object, optionally filtering by type
 * ---------------------------------------------------------------------------*/

yyjson_val *
get_val (yyjson_val *tree, const char *name, yyjson_type type)
{
  yyjson_val *val = yyjson_obj_get (tree, name);
  if (val == NULL)
    return NULL;
  if (type != 0 && yyjson_get_type (val) != type)
    return NULL;
  return val;
}

/* ---------------------------------------------------------------------------
 * safe_strdup / safe_malloc -- abort on failure
 * ---------------------------------------------------------------------------*/

char *
safe_strdup (const char *src)
{
  char *dst = NULL;

  if (src == NULL)
    return NULL;
  dst = strdup (src);
  if (dst == NULL)
    abort ();
  return dst;
}

void *
safe_malloc (size_t size)
{
  void *ret = NULL;
  if (size == 0)
    abort ();
  ret = calloc (1, size);
  if (ret == NULL)
    abort ();
  return ret;
}

/* ---------------------------------------------------------------------------
 * common_safe_* -- numeric string conversions
 * ---------------------------------------------------------------------------*/

int
common_safe_double (const char *numstr, double *converted)
{
  char *err_str = NULL;
  double d;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  d = strtod (numstr, &err_str);
  if (errno > 0)
    return -errno;

  if (err_str == NULL || err_str == numstr || *err_str != '\0')
    return -EINVAL;

  *converted = d;
  return 0;
}

int
common_safe_uint8 (const char *numstr, uint8_t *converted)
{
  char *err = NULL;
  unsigned long int uli;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  uli = strtoul (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  if (uli > UINT8_MAX)
    return -ERANGE;

  *converted = (uint8_t) uli;
  return 0;
}

int
common_safe_uint16 (const char *numstr, uint16_t *converted)
{
  char *err = NULL;
  unsigned long int uli;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  uli = strtoul (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  if (uli > UINT16_MAX)
    return -ERANGE;

  *converted = (uint16_t) uli;
  return 0;
}

int
common_safe_uint32 (const char *numstr, uint32_t *converted)
{
  char *err = NULL;
  unsigned long long int ull;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  ull = strtoull (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  if (ull > UINT32_MAX)
    return -ERANGE;

  *converted = (uint32_t) ull;
  return 0;
}

int
common_safe_uint64 (const char *numstr, uint64_t *converted)
{
  char *err = NULL;
  unsigned long long int ull;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  ull = strtoull (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  *converted = (uint64_t) ull;
  return 0;
}

int
common_safe_uint (const char *numstr, unsigned int *converted)
{
  char *err = NULL;
  unsigned long long int ull;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  ull = strtoull (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  if (ull > UINT_MAX)
    return -ERANGE;

  *converted = (unsigned int) ull;
  return 0;
}

int
common_safe_int8 (const char *numstr, int8_t *converted)
{
  char *err = NULL;
  long int li;

  if (numstr == NULL)
    {
      return -EINVAL;
    }

  errno = 0;
  li = strtol (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  if (li > INT8_MAX || li < INT8_MIN)
    return -ERANGE;

  *converted = (int8_t) li;
  return 0;
}

int
common_safe_int16 (const char *numstr, int16_t *converted)
{
  char *err = NULL;
  long int li;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  li = strtol (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  if (li > INT16_MAX || li < INT16_MIN)
    return -ERANGE;

  *converted = (int16_t) li;
  return 0;
}

int
common_safe_int32 (const char *numstr, int32_t *converted)
{
  char *err = NULL;
  long long int lli;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  lli = strtol (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  if (lli > INT32_MAX || lli < INT32_MIN)

    return -ERANGE;

  *converted = (int32_t) lli;
  return 0;
}

int
common_safe_int64 (const char *numstr, int64_t *converted)
{
  char *err = NULL;
  long long int lli;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  lli = strtoll (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  *converted = (int64_t) lli;
  return 0;
}

int
common_safe_int (const char *numstr, int *converted)
{
  char *err = NULL;
  long long int lli;

  if (numstr == NULL)
    return -EINVAL;

  errno = 0;
  lli = strtol (numstr, &err, 0);
  if (errno > 0)
    return -errno;

  if (err == NULL || err == numstr || *err != '\0')
    return -EINVAL;

  if (lli > INT_MAX || lli < INT_MIN)
    return -ERANGE;

  *converted = (int) lli;
  return 0;
}

/* ---------------------------------------------------------------------------
 * gen_json_map_* / make_json_map_* / free_json_map_* / append_json_map_*
 * ---------------------------------------------------------------------------*/

json_gen_status
gen_json_map_int_int (void *ctx, const json_map_int_int *map, const struct parser_context *ptx, parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  json_gen_ctx *g = (json_gen_ctx *) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 0);
  stat = json_gen_map_open (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  for (i = 0; i < len; i++)
    {
      char numstr[MAX_NUM_STR_LEN];
      int nret;
      nret = snprintf (numstr, sizeof (numstr), "%lld", (long long int) map->keys[i]);
      if (nret < 0 || (size_t) nret >= sizeof (numstr))
        {
          if (! *err)
            *err = strdup ("Error to print string");
          return json_gen_in_error_state;
        }
      stat = json_gen_string (g, numstr, strlen (numstr));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = map_int (g, map->values[i]);
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = json_gen_map_close (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 1);
  return json_gen_status_ok;
}

void
free_json_map_int_int (json_map_int_int *map)
{
  if (map != NULL)
    {
      free (map->keys);
      map->keys = NULL;
      free (map->values);
      map->values = NULL;
      free (map);
    }
}

define_cleaner_function (json_map_int_int *, free_json_map_int_int)

json_map_int_int *
make_json_map_int_int (yyjson_val *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_int) json_map_int_int *ret = NULL;
  size_t i;
  size_t len;
  yyjson_obj_iter iter;
  yyjson_val *key;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || ! yyjson_is_obj (src))
    return NULL;

  len = yyjson_obj_size (src);
  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    return NULL;

  ret->len = 0;
  ret->keys = calloc (len + 1, sizeof (int));
  if (ret->keys == NULL)
    {
      return NULL;
    }

  ret->values = calloc (len + 1, sizeof (int));
  if (ret->values == NULL)
    {
      return NULL;
    }

  i = 0;
  yyjson_obj_iter_init (src, &iter);
  while ((key = yyjson_obj_iter_next (&iter)) != NULL)
    {
      const char *srckey = yyjson_get_str (key);
      yyjson_val *srcval = yyjson_obj_iter_get_val (key);

      ret->keys[i] = 0;
      ret->values[i] = 0;
      ret->len = i + 1;

      if (srckey != NULL)
        {
          int invalid = common_safe_int (srckey, &(ret->keys[i]));
          if (invalid)
            {
              if (*err == NULL
                  && asprintf (err, "Invalid key '%s' with type 'int': %s", srckey, strerror (-invalid)) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
        }

      if (srcval != NULL)
        {
          int invalid;
          if (! yyjson_is_raw (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          invalid = common_safe_int (yyjson_get_raw (srcval), &(ret->values[i]));
          if (invalid)
            {
              if (*err == NULL
                  && asprintf (err, "Invalid value with type 'int' for key '%s': %s", srckey, strerror (-invalid)) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
        }
      i++;
    }
  return move_ptr (ret);
}

int
append_json_map_int_int (json_map_int_int *map, int key, int val)
{
  size_t len;
  __auto_free int *keys = NULL;
  __auto_free int *vals = NULL;

  if (map == NULL)
    return -1;

  if ((SIZE_MAX / sizeof (int) - 1) < map->len)
    return -1;

  len = map->len + 1;
  keys = calloc (1, len * sizeof (int));
  if (keys == NULL)
    return -1;
  vals = calloc (1, len * sizeof (int));
  if (vals == NULL)
    {
      return -1;
    }

  if (map->len)
    {
      (void) memcpy (keys, map->keys, map->len * sizeof (int));
      (void) memcpy (vals, map->values, map->len * sizeof (int));
    }
  free (map->keys);
  map->keys = keys;
  keys = NULL;
  free (map->values);
  map->values = vals;
  vals = NULL;
  map->keys[map->len] = key;
  map->values[map->len] = val;

  map->len++;
  return 0;
}

json_gen_status
gen_json_map_int_bool (void *ctx, const json_map_int_bool *map, const struct parser_context *ptx, parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  json_gen_ctx *g = (json_gen_ctx *) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 0);
  stat = json_gen_map_open (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  for (i = 0; i < len; i++)
    {
      char numstr[MAX_NUM_STR_LEN];
      int nret;
      nret = snprintf (numstr, sizeof (numstr), "%lld", (long long int) map->keys[i]);
      if (nret < 0 || (size_t) nret >= sizeof (numstr))
        {
          if (! *err)
            *err = strdup ("Error to print string");
          return json_gen_in_error_state;
        }
      stat = json_gen_string (g, numstr, strlen (numstr));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = json_gen_bool (g, (int) (map->values[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = json_gen_map_close (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 1);
  return json_gen_status_ok;
}

void
free_json_map_int_bool (json_map_int_bool *map)
{
  if (map != NULL)
    {
      size_t i;
      for (i = 0; i < map->len; i++)
        {
          // No need to free key for type int
          // No need to free value for type bool
        }
      free (map->keys);
      map->keys = NULL;
      free (map->values);
      map->values = NULL;
      free (map);
    }
}

define_cleaner_function (json_map_int_bool *, free_json_map_int_bool)

json_map_int_bool *
make_json_map_int_bool (yyjson_val *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_bool) json_map_int_bool *ret = NULL;
  size_t i;
  size_t len;
  yyjson_obj_iter iter;
  yyjson_val *key;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || ! yyjson_is_obj (src))
    return NULL;

  len = yyjson_obj_size (src);
  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    return NULL;
  ret->len = 0;
  ret->keys = calloc (len + 1, sizeof (int));
  if (ret->keys == NULL)
    {
      return NULL;
    }
  ret->values = calloc (len + 1, sizeof (bool));
  if (ret->values == NULL)
    {
      return NULL;
    }

  i = 0;
  yyjson_obj_iter_init (src, &iter);
  while ((key = yyjson_obj_iter_next (&iter)) != NULL)
    {
      const char *srckey = yyjson_get_str (key);
      yyjson_val *srcval = yyjson_obj_iter_get_val (key);

      ret->keys[i] = 0;
      ret->values[i] = false;
      ret->len = i + 1;

      if (srckey != NULL)
        {
          int invalid = common_safe_int (srckey, &(ret->keys[i]));
          if (invalid)
            {
              if (*err == NULL
                  && asprintf (err, "Invalid key '%s' with type 'int': %s", srckey, strerror (-invalid)) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
        }

      if (srcval != NULL)
        {
          if (yyjson_is_true (srcval))
            ret->values[i] = true;
          else if (yyjson_is_false (srcval))
            ret->values[i] = false;
          else
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'bool' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
        }
      i++;
    }
  return move_ptr (ret);
}

int
append_json_map_int_bool (json_map_int_bool *map, int key, bool val)
{
  size_t len;
  __auto_free int *keys = NULL;
  __auto_free bool *vals = NULL;

  if (map == NULL)
    return -1;

  if ((SIZE_MAX / sizeof (int) - 1) < map->len || (SIZE_MAX / sizeof (bool) - 1) < map->len)
    return -1;

  len = map->len + 1;
  keys = calloc (len, sizeof (int));
  if (keys == NULL)
    return -1;
  vals = calloc (len, sizeof (bool));
  if (vals == NULL)
    {
      return -1;
    }

  if (map->len)
    {
      (void) memcpy (keys, map->keys, map->len * sizeof (int));
      (void) memcpy (vals, map->values, map->len * sizeof (bool));
    }
  free (map->keys);
  map->keys = keys;
  keys = NULL;
  free (map->values);
  map->values = vals;
  vals = NULL;
  map->keys[map->len] = key;
  map->values[map->len] = val;

  map->len++;
  return 0;
}

json_gen_status
gen_json_map_int_string (void *ctx, const json_map_int_string *map, const struct parser_context *ptx, parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  json_gen_ctx *g = (json_gen_ctx *) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 0);

  stat = json_gen_map_open (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  for (i = 0; i < len; i++)
    {
      char numstr[MAX_NUM_STR_LEN];
      int nret;
      nret = snprintf (numstr, sizeof (numstr), "%lld", (long long int) map->keys[i]);
      if (nret < 0 || (size_t) nret >= sizeof (numstr))
        {
          if (! *err)
            *err = strdup ("Error to print string");
          return json_gen_in_error_state;
        }
      stat = json_gen_string (g, numstr, strlen (numstr));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = json_gen_string (g, map->values[i], strlen (map->values[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = json_gen_map_close (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 1);
  return json_gen_status_ok;
}

void
free_json_map_int_string (json_map_int_string *map)
{
  if (map != NULL)
    {
      size_t i;
      for (i = 0; i < map->len; i++)
        {
          // No need to free key for type int
          free (map->values[i]);
          map->values[i] = NULL;
        }
      free (map->keys);
      map->keys = NULL;
      free (map->values);
      map->values = NULL;
      free (map);
    }
}

define_cleaner_function (json_map_int_string *, free_json_map_int_string)

json_map_int_string *
make_json_map_int_string (yyjson_val *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_string) json_map_int_string *ret = NULL;
  size_t i;
  size_t len;
  yyjson_obj_iter iter;
  yyjson_val *key;

  if (src == NULL || ! yyjson_is_obj (src))
    return NULL;

  (void) ctx; /* Silence compiler warning.  */

  len = yyjson_obj_size (src);

  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    return NULL;

  ret->len = 0;
  ret->keys = calloc (len + 1, sizeof (int));
  if (ret->keys == NULL)
    {
      return NULL;
    }

  ret->values = calloc (len + 1, sizeof (char *));
  if (ret->values == NULL)
    {
      return NULL;
    }

  i = 0;
  yyjson_obj_iter_init (src, &iter);
  while ((key = yyjson_obj_iter_next (&iter)) != NULL)
    {
      const char *srckey = yyjson_get_str (key);
      yyjson_val *srcval = yyjson_obj_iter_get_val (key);

      ret->keys[i] = 0;
      ret->values[i] = NULL;
      ret->len = i + 1;

      if (srckey != NULL)
        {
          int invalid;
          invalid = common_safe_int (srckey, &(ret->keys[i]));
          if (invalid)
            {
              if (*err == NULL
                  && asprintf (err, "Invalid key '%s' with type 'int': %s", srckey, strerror (-invalid)) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
        }

      if (srcval != NULL)
        {
          const char *str;
          if (! yyjson_is_str (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'string' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          str = yyjson_get_str (srcval);
          ret->values[i] = strdup (str ? str : "");
        }
      i++;
    }
  return move_ptr (ret);
}

int
append_json_map_int_string (json_map_int_string *map, int key, const char *val)
{
  size_t len;
  int *keys = NULL;
  char **vals = NULL;
  char *new_value;

  if (map == NULL)
    return -1;

  if ((SIZE_MAX / sizeof (int) - 1) < map->len || (SIZE_MAX / sizeof (char *) - 1) < map->len)
    return -1;

  len = map->len + 1;
  keys = realloc (map->keys, len * sizeof (int));
  if (keys == NULL)
    return -1;
  map->keys = keys;

  vals = realloc (map->values, len * sizeof (char *));
  if (vals == NULL)
    return -1;
  map->values = vals;

  new_value = strdup (val ? val : "");
  if (new_value == NULL)
    return -1;

  map->keys[map->len] = key;
  map->values[map->len] = new_value;

  map->len++;
  return 0;
}

json_gen_status
gen_json_map_string_int (void *ctx, const json_map_string_int *map, const struct parser_context *ptx, parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  json_gen_ctx *g = (json_gen_ctx *) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 0);
  stat = json_gen_map_open (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  for (i = 0; i < len; i++)
    {
      stat = json_gen_string (g, map->keys[i], strlen (map->keys[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = map_int (g, map->values[i]);
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = json_gen_map_close (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 1);
  return json_gen_status_ok;
}

void
free_json_map_string_int (json_map_string_int *map)
{
  if (map != NULL)
    {
      size_t i;
      for (i = 0; i < map->len; i++)
        {
          free (map->keys[i]);
          map->keys[i] = NULL;
        }
      free (map->keys);
      map->keys = NULL;
      free (map->values);
      map->values = NULL;
      free (map);
    }
}

define_cleaner_function (json_map_string_int *, free_json_map_string_int)

json_map_string_int *
make_json_map_string_int (yyjson_val *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_string_int) json_map_string_int *ret = NULL;
  size_t i;
  size_t len;
  yyjson_obj_iter iter;
  yyjson_val *key;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || ! yyjson_is_obj (src))
    return NULL;

  len = yyjson_obj_size (src);
  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    {
      *(err) = strdup ("error allocating memory");
      return NULL;
    }
  ret->len = 0;
  ret->keys = calloc (len + 1, sizeof (char *));
  if (ret->keys == NULL)
    {
      *(err) = strdup ("error allocating memory");
      return NULL;
    }
  ret->values = calloc (len + 1, sizeof (int));
  if (ret->values == NULL)
    {
      *(err) = strdup ("error allocating memory");
      return NULL;
    }

  i = 0;
  yyjson_obj_iter_init (src, &iter);
  while ((key = yyjson_obj_iter_next (&iter)) != NULL)
    {
      const char *srckey = yyjson_get_str (key);
      yyjson_val *srcval = yyjson_obj_iter_get_val (key);

      ret->keys[i] = NULL;
      ret->values[i] = 0;
      ret->len = i + 1;

      ret->keys[i] = strdup (srckey ? srckey : "");
      if (ret->keys[i] == NULL)
        {
          *(err) = strdup ("error allocating memory");
          return NULL;
        }

      if (srcval != NULL)
        {
          int invalid;
          if (! yyjson_is_raw (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          invalid = common_safe_int (yyjson_get_raw (srcval), &(ret->values[i]));
          if (invalid)
            {
              if (*err == NULL
                  && asprintf (err, "Invalid value with type 'int' for key '%s': %s", srckey, strerror (-invalid)) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
        }
      i++;
    }
  return move_ptr (ret);
}

int
append_json_map_string_int (json_map_string_int *map, const char *key, int val)
{
  size_t len;
  char **keys = NULL;
  int *vals = NULL;
  char *new_value;

  if (map == NULL)
    return -1;

  if ((SIZE_MAX / sizeof (char *) - 1) < map->len || (SIZE_MAX / sizeof (int) - 1) < map->len)
    return -1;

  len = map->len + 1;
  keys = realloc (map->keys, len * sizeof (char *));
  if (keys == NULL)
    return -1;
  map->keys = keys;
  vals = realloc (map->values, len * sizeof (int));
  if (vals == NULL)
    return -1;
  map->values = vals;

  new_value = strdup (key ? key : "");
  if (new_value == NULL)
    return -1;
  map->keys[map->len] = new_value;
  map->values[map->len] = val;

  map->len++;
  return 0;
}

json_gen_status
gen_json_map_string_int64 (void *ctx, const json_map_string_int64 *map, const struct parser_context *ptx,
                           parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  json_gen_ctx *g = (json_gen_ctx *) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 0);
  stat = json_gen_map_open (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);

  for (i = 0; i < len; i++)
    {
      stat = json_gen_string (g, map->keys[i], strlen (map->keys[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = map_int (g, map->values[i]);
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = json_gen_map_close (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 1);
  return json_gen_status_ok;
}

void
free_json_map_string_int64 (json_map_string_int64 *map)
{
  if (map != NULL)
    {
      size_t i;
      for (i = 0; i < map->len; i++)
        {
          free (map->keys[i]);
          map->keys[i] = NULL;
        }
      free (map->keys);
      map->keys = NULL;
      free (map->values);
      map->values = NULL;
      free (map);
    }
}

define_cleaner_function (json_map_string_int64 *, free_json_map_string_int64)

json_map_string_int64 *
make_json_map_string_int64 (yyjson_val *src, const struct parser_context *ctx,
                            parser_error *err)
{
  __auto_cleanup (free_json_map_string_int64) json_map_string_int64 *ret = NULL;

  (void) ctx; /* Silence compiler warning.  */

  if (src != NULL && yyjson_is_obj (src))
    {
      size_t i;
      size_t len = yyjson_obj_size (src);
      yyjson_obj_iter iter;
      yyjson_val *key;

      ret = safe_malloc (sizeof (*ret));
      ret->len = len;
      ret->keys = safe_malloc ((len + 1) * sizeof (char *));
      ret->values = safe_malloc ((len + 1) * sizeof (int64_t));

      i = 0;
      yyjson_obj_iter_init (src, &iter);
      while ((key = yyjson_obj_iter_next (&iter)) != NULL)
        {
          const char *srckey = yyjson_get_str (key);
          yyjson_val *srcval = yyjson_obj_iter_get_val (key);

          ret->keys[i] = safe_strdup (srckey ? srckey : "");

          if (srcval != NULL)
            {
              int64_t invalid;
              if (! yyjson_is_raw (srcval))
                {
                  if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                    {
                      *(err) = safe_strdup ("error allocating memory");
                    }
                  return NULL;
                }
              invalid = common_safe_int64 (yyjson_get_raw (srcval), &(ret->values[i]));
              if (invalid)
                {
                  if (*err == NULL
                      && asprintf (err, "Invalid value with type 'int' for key '%s': %s", srckey, strerror (-invalid))
                             < 0)
                    {
                      *(err) = safe_strdup ("error allocating memory");
                    }
                  return NULL;
                }
            }
          i++;
        }
    }
  return move_ptr (ret);
}
int
append_json_map_string_int64 (json_map_string_int64 *map, const char *key, int64_t val)
{
  size_t len;
  char **keys = NULL;
  int64_t *vals = NULL;

  if (map == NULL)
    return -1;

  if ((SIZE_MAX / sizeof (char *) - 1) < map->len || (SIZE_MAX / sizeof (int) - 1) < map->len)
    return -1;

  len = map->len + 1;
  keys = safe_malloc (len * sizeof (char *));
  vals = safe_malloc (len * sizeof (int64_t));

  if (map->len)
    {
      (void) memcpy (keys, map->keys, map->len * sizeof (char *));
      (void) memcpy (vals, map->values, map->len * sizeof (int64_t));
    }
  free (map->keys);
  map->keys = keys;
  free (map->values);
  map->values = vals;
  map->keys[map->len] = safe_strdup (key ? key : "");
  map->values[map->len] = val;

  map->len++;
  return 0;
}

json_gen_status
gen_json_map_string_bool (void *ctx, const json_map_string_bool *map, const struct parser_context *ptx,
                          parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  json_gen_ctx *g = (json_gen_ctx *) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 0);
  stat = json_gen_map_open (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  for (i = 0; i < len; i++)
    {
      stat = json_gen_string (g, map->keys[i], strlen (map->keys[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = json_gen_bool (g, (int) (map->values[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = json_gen_map_close (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 1);
  return json_gen_status_ok;
}

void
free_json_map_string_bool (json_map_string_bool *map)
{
  if (map != NULL)
    {
      size_t i;
      for (i = 0; i < map->len; i++)
        {
          free (map->keys[i]);
          map->keys[i] = NULL;
          // No need to free value for type bool
        }
      free (map->keys);
      map->keys = NULL;
      free (map->values);
      map->values = NULL;
      free (map);
    }
}

define_cleaner_function (json_map_string_bool *, free_json_map_string_bool)

json_map_string_bool *
make_json_map_string_bool (yyjson_val *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_string_bool) json_map_string_bool *ret = NULL;
  size_t i;
  size_t len;
  yyjson_obj_iter iter;
  yyjson_val *key;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || ! yyjson_is_obj (src))
    return NULL;

  len = yyjson_obj_size (src);

  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    return NULL;
  ret->len = 0;
  ret->keys = calloc (len + 1, sizeof (char *));
  if (ret->keys == NULL)
    {
      return NULL;
    }

  ret->values = calloc (len + 1, sizeof (bool));
  if (ret->values == NULL)
    {
      return NULL;
    }

  i = 0;
  yyjson_obj_iter_init (src, &iter);
  while ((key = yyjson_obj_iter_next (&iter)) != NULL)
    {
      const char *srckey = yyjson_get_str (key);
      yyjson_val *srcval = yyjson_obj_iter_get_val (key);

      ret->keys[i] = NULL;
      ret->values[i] = false;
      ret->len = i + 1;

      ret->keys[i] = strdup (srckey ? srckey : "");
      if (ret->keys[i] == NULL)
        {
          *(err) = strdup ("error allocating memory");
          return NULL;
        }
      if (srcval != NULL)
        {
          if (yyjson_is_true (srcval))
            ret->values[i] = true;
          else if (yyjson_is_false (srcval))
            ret->values[i] = false;
          else
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'bool' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
        }
      i++;
    }
  return move_ptr (ret);
}

int
append_json_map_string_bool (json_map_string_bool *map, const char *key, bool val)
{
  size_t len;
  __auto_free char **keys = NULL;
  __auto_free bool *vals = NULL;
  __auto_free char *new_value = NULL;

  if (map == NULL)
    return -1;

  if ((SIZE_MAX / sizeof (char *) - 1) < map->len || (SIZE_MAX / sizeof (bool) - 1) < map->len)
    return -1;

  len = map->len + 1;
  keys = calloc (len, sizeof (char *));
  if (keys == NULL)
    return -1;
  vals = calloc (len, sizeof (bool));
  if (vals == NULL)
    {
      return -1;
    }

  new_value = strdup (key ? key : "");
  if (new_value == NULL)
    {
      return -1;
    }

  if (map->len)
    {
      (void) memcpy (keys, map->keys, map->len * sizeof (char *));
      (void) memcpy (vals, map->values, map->len * sizeof (bool));
    }
  free (map->keys);
  map->keys = keys;
  keys = NULL;
  free (map->values);
  map->values = vals;
  vals = NULL;
  map->keys[map->len] = new_value;
  new_value = NULL;
  map->values[map->len] = val;

  map->len++;
  return 0;
}

json_gen_status
gen_json_map_string_string (void *ctx, const json_map_string_string *map, const struct parser_context *ptx,
                            parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  json_gen_ctx *g = (json_gen_ctx *) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;

  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 0);

  stat = json_gen_map_open (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);

  for (i = 0; i < len; i++)
    {
      stat = json_gen_string (g, map->keys[i], strlen (map->keys[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = json_gen_string (g, map->values[i], strlen (map->values[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = json_gen_map_close (g);
  if (json_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    json_gen_config (g, json_gen_beautify, 1);
  return json_gen_status_ok;
}

void
free_json_map_string_string (json_map_string_string *map)
{
  if (map != NULL)
    {
      size_t i;
      for (i = 0; i < map->len; i++)
        {
          free (map->keys[i]);
          map->keys[i] = NULL;
          free (map->values[i]);
          map->values[i] = NULL;
        }
      free (map->keys);
      map->keys = NULL;
      free (map->values);
      map->values = NULL;
      free (map);
    }
}

define_cleaner_function (json_map_string_string *, free_json_map_string_string)

json_map_string_string *
make_json_map_string_string (yyjson_val *src, const struct parser_context *ctx,
                             parser_error *err)
{
  __auto_cleanup (free_json_map_string_string) json_map_string_string *ret = NULL;
  size_t i;
  size_t len;
  yyjson_obj_iter iter;
  yyjson_val *key;

  (void) ctx; /* Silence compiler warning.  */
  if (src == NULL || ! yyjson_is_obj (src))
    return NULL;

  len = yyjson_obj_size (src);

  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    {
      *(err) = strdup ("error allocating memory");
      return NULL;
    }

  ret->len = 0;

  ret->keys = calloc (len + 1, sizeof (char *));
  if (ret->keys == NULL)
    {
      *(err) = strdup ("error allocating memory");
      return NULL;
    }

  ret->values = calloc (len + 1, sizeof (char *));
  if (ret->values == NULL)
    {
      *(err) = strdup ("error allocating memory");
      return NULL;
    }

  i = 0;
  yyjson_obj_iter_init (src, &iter);
  while ((key = yyjson_obj_iter_next (&iter)) != NULL)
    {
      const char *srckey = yyjson_get_str (key);
      yyjson_val *srcval = yyjson_obj_iter_get_val (key);

      ret->keys[i] = NULL;
      ret->values[i] = NULL;
      ret->len = i + 1;

      ret->keys[i] = strdup (srckey ? srckey : "");
      if (ret->keys[i] == NULL)
        {
          return NULL;
        }
      if (srcval != NULL)
        {
          const char *str;
          if (! yyjson_is_str (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'string' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }

          str = yyjson_get_str (srcval);

          ret->values[i] = strdup (str ? str : "");
          if (ret->values[i] == NULL)
            {
              return NULL;
            }
        }
      i++;
    }
  return move_ptr (ret);
}

json_map_string_string *
clone_map_string_string (json_map_string_string *src)
{
  __auto_cleanup (free_json_map_string_string) json_map_string_string *ret = NULL;
  size_t i;

  if (src == NULL)
    return NULL;

  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    return NULL;

  ret->len = src->len;

  ret->keys = calloc (src->len + 1, sizeof (char *));
  if (ret->keys == NULL)
    return NULL;

  ret->values = calloc (src->len + 1, sizeof (char *));
  if (ret->values == NULL)
    return NULL;

  for (i = 0; i < src->len; i++)
    {
      ret->keys[i] = strdup (src->keys[i]);
      if (ret->keys[i] == NULL)
        return NULL;

      ret->values[i] = strdup (src->values[i]);
      if (ret->values[i] == NULL)
        return NULL;
    }
  return move_ptr (ret);
}

int
append_json_map_string_string (json_map_string_string *map, const char *key, const char *val)
{
  size_t len, i;
  __auto_free char **keys = NULL;
  __auto_free char **values = NULL;
  __auto_free char *new_key = NULL;
  __auto_free char *new_value = NULL;

  if (map == NULL)
    return -1;

  for (i = 0; i < map->len; i++)
    {
      if (strcmp (map->keys[i], key) == 0)
        {
          char *v = strdup (val ? val : "");
          if (v == NULL)
            return -1;
          free (map->values[i]);
          map->values[i] = v;
          return 0;
        }
    }

  if ((SIZE_MAX / sizeof (char *) - 1) < map->len)
    return -1;

  new_key = strdup (key ? key : "");
  if (new_key == NULL)
    return -1;

  new_value = strdup (val ? val : "");
  if (new_value == NULL)
    return -1;

  len = map->len + 1;
  keys = realloc (map->keys, len * sizeof (char *));
  if (keys == NULL)
    return -1;
  map->keys = keys;
  keys = NULL;
  map->keys[map->len] = NULL;

  values = realloc (map->values, len * sizeof (char *));
  if (values == NULL)
    return -1;

  map->keys[map->len] = new_key;
  new_key = NULL;
  map->values = values;
  values = NULL;
  map->values[map->len] = new_value;
  new_value = NULL;

  map->len++;
  return 0;
}

/* ---------------------------------------------------------------------------
 * json_marshal_string -- marshal a C string to a JSON string value
 * ---------------------------------------------------------------------------*/

static void
cleanup_json_gen_ctx (json_gen_ctx *g)
{
  if (! g)
    return;
  json_gen_free (g);
}

define_cleaner_function (json_gen_ctx *, cleanup_json_gen_ctx)

char *
json_marshal_string (const char *str, size_t length, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (cleanup_json_gen_ctx) json_gen_ctx *g = NULL;
  struct parser_context tmp_ctx = { 0 };
  const char *gen_buf = NULL;
  char *json_buf = NULL;
  size_t gen_len = 0;
  json_gen_status stat;

  if (str == NULL || err == NULL)
    return NULL;

  *err = NULL;
  if (ctx == NULL)
    ctx = (const struct parser_context *) (&tmp_ctx);

  if (! json_gen_init (&g, ctx))
    {
      *err = strdup ("Json_gen init failed");
      return json_buf;
    }
  stat = json_gen_string (g, str, length);
  if (json_gen_status_ok != stat)
    {
      if (asprintf (err, "error generating json, errcode: %d", (int) stat) < 0)
        *err = strdup ("error allocating memory");
      return json_buf;
    }
  json_gen_get_buf (g, &gen_buf, &gen_len);
  if (gen_buf == NULL)
    {
      *err = strdup ("Error to get generated json");
      return json_buf;
    }

  json_buf = calloc (1, gen_len + 1);
  if (json_buf == NULL)
    {
      *err = strdup ("error allocating memory");
      return json_buf;
    }

  (void) memcpy (json_buf, gen_buf, gen_len);
  json_buf[gen_len] = '\0';

  return json_buf;
}
