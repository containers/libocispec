#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "ocispec/json_common.h"

#define MAX_NUM_STR_LEN 21

/* ---------------------------------------------------------------------------
 * Streaming JSON generator -- wraps json-c object building
 * ---------------------------------------------------------------------------*/

static json_gen_status
add_value (json_gen_ctx *g, json_object *val)
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
      if (g->pending_key[g->depth] != NULL)
        {
          json_object_object_add (g->stack[g->depth], g->pending_key[g->depth], val);
          free (g->pending_key[g->depth]);
          g->pending_key[g->depth] = NULL;
        }
      else
        {
          json_object_put (val);
          return json_gen_in_error_state;
        }
    }
  else
    {
      json_object_array_add (g->stack[g->depth], val);
    }

  return json_gen_status_ok;
}

json_gen_status
json_gen_map_open (json_gen_ctx *g)
{
  json_object *obj;

  if (g->depth + 1 >= JSON_GEN_MAX_DEPTH)
    return json_gen_in_error_state;

  obj = json_object_new_object ();
  if (obj == NULL)
    return json_gen_in_error_state;

  g->depth++;
  g->stack[g->depth] = obj;
  g->is_map[g->depth] = true;
  g->pending_key[g->depth] = NULL;

  return json_gen_status_ok;
}

json_gen_status
json_gen_map_close (json_gen_ctx *g)
{
  json_object *obj;

  if (g->depth < 0)
    return json_gen_in_error_state;

  obj = g->stack[g->depth];
  g->depth--;

  return add_value (g, obj);
}

json_gen_status
json_gen_array_open (json_gen_ctx *g)
{
  json_object *arr;

  if (g->depth + 1 >= JSON_GEN_MAX_DEPTH)
    return json_gen_in_error_state;

  arr = json_object_new_array ();
  if (arr == NULL)
    return json_gen_in_error_state;

  g->depth++;
  g->stack[g->depth] = arr;
  g->is_map[g->depth] = false;
  g->pending_key[g->depth] = NULL;

  return json_gen_status_ok;
}

json_gen_status
json_gen_array_close (json_gen_ctx *g)
{
  json_object *arr;

  if (g->depth < 0)
    return json_gen_in_error_state;

  arr = g->stack[g->depth];
  g->depth--;

  return add_value (g, arr);
}

json_gen_status
json_gen_string (json_gen_ctx *g, const char *str, size_t len)
{
  if (g->depth >= 0 && g->is_map[g->depth] && g->pending_key[g->depth] == NULL)
    {
      g->pending_key[g->depth] = strndup (str, len);
      if (g->pending_key[g->depth] == NULL)
        return json_gen_in_error_state;
      return json_gen_status_ok;
    }

  json_object *val;

  if (len > INT_MAX)
    return json_gen_in_error_state;

  val = json_object_new_string_len (str, (int) len);
  return add_value (g, val);
}

json_gen_status
json_gen_number (json_gen_ctx *g, const char *numstr, size_t len)
{
  json_object *val;
  char buf[MAX_NUM_STR_LEN];
  char *endptr;

  if (len >= sizeof (buf))
    return json_gen_in_error_state;
  memcpy (buf, numstr, len);
  buf[len] = '\0';

  if (strchr (buf, '.') || strchr (buf, 'e') || strchr (buf, 'E'))
    {
      double d = strtod (buf, &endptr);
      val = json_object_new_double (d);
    }
  else if (buf[0] == '-')
    {
      long long int lli = strtoll (buf, &endptr, 10);
      val = json_object_new_int64 ((int64_t) lli);
    }
  else
    {
      unsigned long long ull = strtoull (buf, &endptr, 10);
      if (ull > (unsigned long long) INT64_MAX)
        val = json_object_new_uint64 ((uint64_t) ull);
      else
        val = json_object_new_int64 ((int64_t) ull);
    }

  return add_value (g, val);
}

json_gen_status
json_gen_bool (json_gen_ctx *g, int val)
{
  json_object *v = json_object_new_boolean (val);
  return add_value (g, v);
}

json_gen_status
json_gen_double (json_gen_ctx *g, double val)
{
  json_object *v = json_object_new_double (val);
  return add_value (g, v);
}

json_gen_status
json_gen_null (json_gen_ctx *g)
{
  if (g->depth < 0)
    {
      g->root = NULL;
      return json_gen_status_ok;
    }

  if (g->is_map[g->depth])
    {
      if (g->pending_key[g->depth] != NULL)
        {
          json_object_object_add (g->stack[g->depth], g->pending_key[g->depth], NULL);
          free (g->pending_key[g->depth]);
          g->pending_key[g->depth] = NULL;
        }
      else
        {
          return json_gen_in_error_state;
        }
    }
  else
    {
      json_object_array_add (g->stack[g->depth], NULL);
    }

  return json_gen_status_ok;
}

json_gen_status
json_gen_get_buf (json_gen_ctx *g, const char **buf, size_t *len)
{
  const char *str;
  int flags = JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_NOSLASHESCAPE;

  if (g->buf != NULL)
    {
      free (g->buf);
      g->buf = NULL;
    }

  if (g->beautify)
    flags |= JSON_C_TO_STRING_PRETTY;

  if (g->root == NULL)
    return json_gen_in_error_state;

  str = json_object_to_json_string_ext (g->root, flags);
  if (str == NULL)
    return json_gen_in_error_state;

  g->buf = strdup (str);
  if (g->buf == NULL)
    return json_gen_in_error_state;
  g->buf_len = strlen (g->buf);

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
  int i;

  if (g == NULL)
    return;
  if (g->buf != NULL)
    free (g->buf);
  if (g->root != NULL)
    json_object_put (g->root);
  for (i = 0; i <= g->depth; i++)
    {
      free (g->pending_key[i]);
      json_object_put (g->stack[i]);
    }
  free (g);
}

/* ---------------------------------------------------------------------------
 * Residual generation -- parse stored JSON string, inject into gen context
 * ---------------------------------------------------------------------------*/

static json_gen_status
gen_json_val (json_object *val, json_gen_ctx *g, parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;
  enum json_type type;

  if (val == NULL)
    {
      stat = json_gen_null (g);
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      return json_gen_status_ok;
    }

  type = json_object_get_type (val);

  switch (type)
    {
    case json_type_string:
      {
        const char *str = json_object_get_string (val);
        if (str == NULL)
          return stat;
        stat = json_gen_string (g, str, strlen (str));
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    case json_type_int:
      {
        char numstr[MAX_NUM_STR_LEN];
        int nret;
        uint64_t uval = json_object_get_uint64 (val);
        int64_t sval = json_object_get_int64 (val);
        if (sval < 0)
          nret = snprintf (numstr, sizeof (numstr), "%lld", (long long) sval);
        else
          nret = snprintf (numstr, sizeof (numstr), "%llu", (unsigned long long) uval);
        if (nret < 0 || (size_t) nret >= sizeof (numstr))
          return json_gen_in_error_state;
        stat = json_gen_number (g, numstr, strlen (numstr));
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    case json_type_double:
      {
        double d = json_object_get_double (val);
        stat = json_gen_double (g, d);
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    case json_type_boolean:
      stat = json_gen_bool (g, json_object_get_boolean (val));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      return json_gen_status_ok;
    case json_type_null:
      stat = json_gen_null (g);
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      return json_gen_status_ok;
    case json_type_object:
      {
        stat = json_gen_map_open (g);
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        json_object_object_foreach (val, key, child)
          {
            stat = json_gen_string (g, key, strlen (key));
            if (json_gen_status_ok != stat)
              GEN_SET_ERROR_AND_RETURN (stat, err);
            stat = gen_json_val (child, g, err);
            if (json_gen_status_ok != stat)
              GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = json_gen_map_close (g);
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        return json_gen_status_ok;
      }
    case json_type_array:
      {
        size_t i, alen;
        stat = json_gen_array_open (g);
        if (json_gen_status_ok != stat)
          GEN_SET_ERROR_AND_RETURN (stat, err);
        alen = json_object_array_length (val);
        for (i = 0; i < alen; i++)
          {
            stat = gen_json_val (json_object_array_get_idx (val, i), g, err);
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
gen_json_object_residual (json_object *residual, json_gen_ctx *g, parser_error *err)
{
  json_gen_status stat = json_gen_status_ok;

  if (residual == NULL)
    return json_gen_status_ok;

  if (! json_object_is_type (residual, json_type_object))
    return json_gen_in_error_state;

  json_object_object_foreach (residual, key, child)
    {
      stat = json_gen_string (g, key, strlen (key));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = gen_json_val (child, g, err);
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }
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

json_object *
get_val (json_object *tree, const char *name, int type)
{
  json_object *val = NULL;

  if (! json_object_object_get_ex (tree, name, &val))
    return NULL;

  if (type == json_c_type_number)
    {
      if (! json_object_is_type (val, json_type_int) && ! json_object_is_type (val, json_type_double))
        return NULL;
    }
  else if (! json_object_is_type (val, (enum json_type) type))
    {
      return NULL;
    }

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
make_json_map_int_int (json_object *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_int) json_map_int_int *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || ! json_object_is_type (src, json_type_object))
    return NULL;

  len = json_object_object_length (src);
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
  json_object_object_foreach (src, srckey, srcval)
    {
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
          const char *numstr;
          if (! json_object_is_type (srcval, json_type_int) && ! json_object_is_type (srcval, json_type_double))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          numstr = json_object_get_string (srcval);
          invalid = common_safe_int (numstr, &(ret->values[i]));
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
make_json_map_int_bool (json_object *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_bool) json_map_int_bool *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || ! json_object_is_type (src, json_type_object))
    return NULL;

  len = json_object_object_length (src);
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
  json_object_object_foreach (src, srckey, srcval)
    {
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
          if (json_object_is_type (srcval, json_type_boolean))
            ret->values[i] = json_object_get_boolean (srcval);
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
      if (map->values[i] == NULL)
        {
          stat = json_gen_null (g);
          if (json_gen_status_ok != stat)
            GEN_SET_ERROR_AND_RETURN (stat, err);
          continue;
        }
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
make_json_map_int_string (json_object *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_string) json_map_int_string *ret = NULL;
  size_t i;
  size_t len;

  if (src == NULL || ! json_object_is_type (src, json_type_object))
    return NULL;

  (void) ctx; /* Silence compiler warning.  */

  len = json_object_object_length (src);

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
  json_object_object_foreach (src, srckey, srcval)
    {
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
          if (! json_object_is_type (srcval, json_type_string))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'string' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          str = json_object_get_string (srcval);
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
      if (map->keys[i] == NULL)
        continue;
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
make_json_map_string_int (json_object *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_string_int) json_map_string_int *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || ! json_object_is_type (src, json_type_object))
    return NULL;

  len = json_object_object_length (src);
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
  json_object_object_foreach (src, srckey, srcval)
    {
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
          const char *numstr;
          if (! json_object_is_type (srcval, json_type_int) && ! json_object_is_type (srcval, json_type_double))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          numstr = json_object_get_string (srcval);
          invalid = common_safe_int (numstr, &(ret->values[i]));
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
      if (map->keys[i] == NULL)
        continue;
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
make_json_map_string_int64 (json_object *src, const struct parser_context *ctx,
                            parser_error *err)
{
  __auto_cleanup (free_json_map_string_int64) json_map_string_int64 *ret = NULL;

  (void) ctx; /* Silence compiler warning.  */

  if (src != NULL && json_object_is_type (src, json_type_object))
    {
      size_t i;
      size_t len = json_object_object_length (src);

      ret = safe_malloc (sizeof (*ret));
      ret->len = len;
      ret->keys = safe_malloc ((len + 1) * sizeof (char *));
      ret->values = safe_malloc ((len + 1) * sizeof (int64_t));

      i = 0;
      json_object_object_foreach (src, srckey, srcval)
        {
          ret->keys[i] = safe_strdup (srckey ? srckey : "");

          if (srcval != NULL)
            {
              int64_t invalid;
              const char *numstr;
              if (! json_object_is_type (srcval, json_type_int) && ! json_object_is_type (srcval, json_type_double))
                {
                  if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                    {
                      *(err) = safe_strdup ("error allocating memory");
                    }
                  return NULL;
                }
              numstr = json_object_get_string (srcval);
              invalid = common_safe_int64 (numstr, &(ret->values[i]));
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
      if (map->keys[i] == NULL)
        continue;
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
make_json_map_string_bool (json_object *src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_string_bool) json_map_string_bool *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || ! json_object_is_type (src, json_type_object))
    return NULL;

  len = json_object_object_length (src);

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
  json_object_object_foreach (src, srckey, srcval)
    {
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
          if (json_object_is_type (srcval, json_type_boolean))
            ret->values[i] = json_object_get_boolean (srcval);
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
      if (map->keys[i] == NULL)
        continue;
      stat = json_gen_string (g, map->keys[i], strlen (map->keys[i]));
      if (json_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      if (map->values[i] == NULL)
        {
          stat = json_gen_null (g);
          if (json_gen_status_ok != stat)
            GEN_SET_ERROR_AND_RETURN (stat, err);
          continue;
        }
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
make_json_map_string_string (json_object *src, const struct parser_context *ctx,
                             parser_error *err)
{
  __auto_cleanup (free_json_map_string_string) json_map_string_string *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */
  if (src == NULL || ! json_object_is_type (src, json_type_object))
    return NULL;

  len = json_object_object_length (src);

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
  json_object_object_foreach (src, srckey, srcval)
    {
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
          if (! json_object_is_type (srcval, json_type_string))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'string' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }

          str = json_object_get_string (srcval);

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
