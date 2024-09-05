#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "ocispec/json_common.h"

#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
#define YAJL_GET_STRING_NO_CHECK(v) ((v)->u.string)

#define MAX_NUM_STR_LEN 21

static yajl_gen_status gen_yajl_val (yajl_val obj, yajl_gen g, parser_error *err);

static yajl_gen_status
gen_yajl_val_obj (yajl_val obj, yajl_gen g, parser_error *err)
{
  size_t i;
  yajl_gen_status stat = yajl_gen_status_ok;

  stat = yajl_gen_map_open (g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);

  for (i = 0; i < obj->u.object.len; i++)
    {
      stat = yajl_gen_string (g, (const unsigned char *) obj->u.object.keys[i], strlen (obj->u.object.keys[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = gen_yajl_val (obj->u.object.values[i], g, err);
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_map_close (g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  return yajl_gen_status_ok;
}

static yajl_gen_status
gen_yajl_val_array (yajl_val arr, yajl_gen g, parser_error *err)
{
  size_t i;
  yajl_gen_status stat = yajl_gen_status_ok;

  stat = yajl_gen_array_open (g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);

  for (i = 0; i < arr->u.array.len; i++)
    {
      stat = gen_yajl_val (arr->u.array.values[i], g, err);
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_array_close (g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  return yajl_gen_status_ok;
}

static yajl_gen_status
gen_yajl_val (yajl_val obj, yajl_gen g, parser_error *err)
{
  yajl_gen_status __stat = yajl_gen_status_ok;
  char *__tstr;

  switch (obj->type)
    {
    case yajl_t_string:
      __tstr = YAJL_GET_STRING (obj);
      if (__tstr == NULL)
        {
          return __stat;
        }
      __stat = yajl_gen_string (g, (const unsigned char *) __tstr, strlen (__tstr));
      if (yajl_gen_status_ok != __stat)
        GEN_SET_ERROR_AND_RETURN (__stat, err);
      return yajl_gen_status_ok;
    case yajl_t_number:
      __tstr = YAJL_GET_NUMBER (obj);
      if (__tstr == NULL)
        {
          return __stat;
        }
      __stat = yajl_gen_number (g, __tstr, strlen (__tstr));
      if (yajl_gen_status_ok != __stat)
        GEN_SET_ERROR_AND_RETURN (__stat, err);
      return yajl_gen_status_ok;
    case yajl_t_object:
      return gen_yajl_val_obj (obj, g, err);
    case yajl_t_array:
      return gen_yajl_val_array (obj, g, err);
    case yajl_t_true:
      return yajl_gen_bool (g, true);
    case yajl_t_false:
      return yajl_gen_bool (g, false);
    case yajl_t_null:
      return yajl_gen_null(g);
    case yajl_t_any:
      return __stat;
    }
  return __stat;
}

yajl_gen_status
gen_yajl_object_residual (yajl_val obj, yajl_gen g, parser_error *err)
{
  size_t i;
  yajl_gen_status stat = yajl_gen_status_ok;

  for (i = 0; i < obj->u.object.len; i++)
    {
      if (obj->u.object.keys[i] == NULL)
        {
          continue;
        }
      stat = yajl_gen_string (g, (const unsigned char *) obj->u.object.keys[i], strlen (obj->u.object.keys[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = gen_yajl_val (obj->u.object.values[i], g, err);
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  return yajl_gen_status_ok;
}

yajl_gen_status
map_uint (void *ctx, long long unsigned int num)
{
  char numstr[MAX_NUM_STR_LEN];
  int ret;

  ret = snprintf (numstr, sizeof (numstr), "%llu", num);
  if (ret < 0 || (size_t) ret >= sizeof (numstr))
    return yajl_gen_in_error_state;
  return yajl_gen_number ((yajl_gen) ctx, (const char *) numstr, strlen (numstr));
}

yajl_gen_status
map_int (void *ctx, long long int num)
{
  char numstr[MAX_NUM_STR_LEN];
  int ret;

  ret = snprintf (numstr, sizeof (numstr), "%lld", num);
  if (ret < 0 || (size_t) ret >= sizeof (numstr))
    return yajl_gen_in_error_state;
  return yajl_gen_number ((yajl_gen) ctx, (const char *) numstr, strlen (numstr));
}

bool
json_gen_init (yajl_gen *g, const struct parser_context *ctx)
{
  *g = yajl_gen_alloc (NULL);
  if (NULL == *g)
    return false;

  yajl_gen_config (*g, yajl_gen_beautify, (int) (! (ctx->options & OPT_GEN_SIMPLIFY)));
  yajl_gen_config (*g, yajl_gen_validate_utf8, (int) (! (ctx->options & OPT_GEN_NO_VALIDATE_UTF8)));
  return true;
}

yajl_val
get_val (yajl_val tree, const char *name, yajl_type type)
{
  const char *path[] = { name, NULL };
  return yajl_tree_get (tree, path, type);
}

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

yajl_gen_status
gen_json_map_int_int (void *ctx, const json_map_int_int *map, const struct parser_context *ptx, parser_error *err)
{
  yajl_gen_status stat = yajl_gen_status_ok;
  yajl_gen g = (yajl_gen) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 0);
  stat = yajl_gen_map_open ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
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
          return yajl_gen_in_error_state;
        }
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) numstr, strlen (numstr));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = map_int (g, map->values[i]);
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_map_close ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 1);
  return yajl_gen_status_ok;
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
make_json_map_int_int (yajl_val src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_int) json_map_int_int *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || YAJL_GET_OBJECT (src) == NULL)
    return NULL;

  len = YAJL_GET_OBJECT_NO_CHECK (src)->len;
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

  for (i = 0; i < len; i++)
    {
      const char *srckey = YAJL_GET_OBJECT_NO_CHECK (src)->keys[i];
      yajl_val srcval = YAJL_GET_OBJECT_NO_CHECK (src)->values[i];

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
          if (! YAJL_IS_NUMBER (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          invalid = common_safe_int (YAJL_GET_NUMBER (srcval), &(ret->values[i]));
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

yajl_gen_status
gen_json_map_int_bool (void *ctx, const json_map_int_bool *map, const struct parser_context *ptx, parser_error *err)
{
  yajl_gen_status stat = yajl_gen_status_ok;
  yajl_gen g = (yajl_gen) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 0);
  stat = yajl_gen_map_open ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
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
          return yajl_gen_in_error_state;
        }
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) numstr, strlen (numstr));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = yajl_gen_bool ((yajl_gen) g, (int) (map->values[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_map_close ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 1);
  return yajl_gen_status_ok;
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
make_json_map_int_bool (yajl_val src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_bool) json_map_int_bool *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || YAJL_GET_OBJECT (src) == NULL)
    return NULL;

  len = YAJL_GET_OBJECT_NO_CHECK (src)->len;
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
  for (i = 0; i < len; i++)
    {
      const char *srckey = YAJL_GET_OBJECT_NO_CHECK (src)->keys[i];
      yajl_val srcval = YAJL_GET_OBJECT_NO_CHECK (src)->values[i];

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
          if (YAJL_IS_TRUE (srcval))
            ret->values[i] = true;
          else if (YAJL_IS_FALSE (srcval))
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

yajl_gen_status
gen_json_map_int_string (void *ctx, const json_map_int_string *map, const struct parser_context *ptx, parser_error *err)
{
  yajl_gen_status stat = yajl_gen_status_ok;
  yajl_gen g = (yajl_gen) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 0);

  stat = yajl_gen_map_open ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
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
          return yajl_gen_in_error_state;
        }
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) numstr, strlen (numstr));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) (map->values[i]), strlen (map->values[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_map_close ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 1);
  return yajl_gen_status_ok;
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
make_json_map_int_string (yajl_val src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_int_string) json_map_int_string *ret = NULL;
  size_t i;
  size_t len;

  if (src == NULL || YAJL_GET_OBJECT (src) == NULL)
    return NULL;

  (void) ctx; /* Silence compiler warning.  */

  len = YAJL_GET_OBJECT_NO_CHECK (src)->len;

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

  for (i = 0; i < len; i++)
    {
      const char *srckey = YAJL_GET_OBJECT_NO_CHECK (src)->keys[i];
      yajl_val srcval = YAJL_GET_OBJECT_NO_CHECK (src)->values[i];

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
          if (! YAJL_IS_STRING (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'string' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          char *str = YAJL_GET_STRING_NO_CHECK (srcval);
          ret->values[i] = strdup (str ? str : "");
        }
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

yajl_gen_status
gen_json_map_string_int (void *ctx, const json_map_string_int *map, const struct parser_context *ptx, parser_error *err)
{
  yajl_gen_status stat = yajl_gen_status_ok;
  yajl_gen g = (yajl_gen) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 0);
  stat = yajl_gen_map_open ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  for (i = 0; i < len; i++)
    {
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) (map->keys[i]), strlen (map->keys[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = map_int (g, map->values[i]);
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_map_close ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 1);
  return yajl_gen_status_ok;
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
make_json_map_string_int (yajl_val src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_string_int) json_map_string_int *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */

  if (src == NULL || YAJL_GET_OBJECT (src) == NULL)
    return NULL;

  len = YAJL_GET_OBJECT_NO_CHECK (src)->len;
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
  for (i = 0; i < len; i++)
    {
      const char *srckey = YAJL_GET_OBJECT_NO_CHECK (src)->keys[i];
      yajl_val srcval = YAJL_GET_OBJECT_NO_CHECK (src)->values[i];

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
          if (! YAJL_IS_NUMBER (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }
          invalid = common_safe_int (YAJL_GET_NUMBER (srcval), &(ret->values[i]));
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

yajl_gen_status
gen_json_map_string_int64 (void *ctx, const json_map_string_int64 *map, const struct parser_context *ptx,
                           parser_error *err)
{
  yajl_gen_status stat = yajl_gen_status_ok;
  yajl_gen g = (yajl_gen) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 0);
  stat = yajl_gen_map_open ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);

  for (i = 0; i < len; i++)
    {
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) (map->keys[i]), strlen (map->keys[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = map_int (g, map->values[i]);
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_map_close ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 1);
  return yajl_gen_status_ok;
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
make_json_map_string_int64 (yajl_val src, const struct parser_context *ctx,
                                                       parser_error *err)
{
  __auto_cleanup (free_json_map_string_int64) json_map_string_int64 *ret = NULL;

  (void) ctx; /* Silence compiler warning.  */

  if (src != NULL && YAJL_GET_OBJECT (src) != NULL)
    {
      size_t i;
      size_t len = YAJL_GET_OBJECT (src)->len;
      ret = safe_malloc (sizeof (*ret));
      ret->len = len;
      ret->keys = safe_malloc ((len + 1) * sizeof (char *));
      ret->values = safe_malloc ((len + 1) * sizeof (int64_t));
      for (i = 0; i < len; i++)
        {
          const char *srckey = YAJL_GET_OBJECT (src)->keys[i];
          yajl_val srcval = YAJL_GET_OBJECT (src)->values[i];
          ret->keys[i] = safe_strdup (srckey ? srckey : "");

          if (srcval != NULL)
            {
              int64_t invalid;
              if (! YAJL_IS_NUMBER (srcval))
                {
                  if (*err == NULL && asprintf (err, "Invalid value with type 'int' for key '%s'", srckey) < 0)
                    {
                      *(err) = safe_strdup ("error allocating memory");
                    }
                  return NULL;
                }
              invalid = common_safe_int64 (YAJL_GET_NUMBER (srcval), &(ret->values[i]));
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

yajl_gen_status
gen_json_map_string_bool (void *ctx, const json_map_string_bool *map, const struct parser_context *ptx,
                          parser_error *err)
{
  yajl_gen_status stat = yajl_gen_status_ok;
  yajl_gen g = (yajl_gen) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 0);
  stat = yajl_gen_map_open ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  for (i = 0; i < len; i++)
    {
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) (map->keys[i]), strlen (map->keys[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = yajl_gen_bool ((yajl_gen) g, (int) (map->values[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_map_close ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 1);
  return yajl_gen_status_ok;
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
make_json_map_string_bool (yajl_val src, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (free_json_map_string_bool) json_map_string_bool *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */

  len = YAJL_GET_OBJECT_NO_CHECK (src)->len;

  if (src == NULL || YAJL_GET_OBJECT (src) == NULL)
    return NULL;

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
  for (i = 0; i < len; i++)
    {
      const char *srckey = YAJL_GET_OBJECT_NO_CHECK (src)->keys[i];
      yajl_val srcval = YAJL_GET_OBJECT_NO_CHECK (src)->values[i];

      ret->keys[i] = NULL;
      ret->values[i] = NULL;
      ret->len = i + 1;

      ret->keys[i] = strdup (srckey ? srckey : "");
      if (ret->keys[i] == NULL)
        {
          *(err) = strdup ("error allocating memory");
          return NULL;
        }
      if (srcval != NULL)
        {
          if (YAJL_IS_TRUE (srcval))
            ret->values[i] = true;
          else if (YAJL_IS_FALSE (srcval))
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

yajl_gen_status
gen_json_map_string_string (void *ctx, const json_map_string_string *map, const struct parser_context *ptx,
                            parser_error *err)
{
  yajl_gen_status stat = yajl_gen_status_ok;
  yajl_gen g = (yajl_gen) ctx;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;

  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 0);

  stat = yajl_gen_map_open ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);

  for (i = 0; i < len; i++)
    {
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) (map->keys[i]), strlen (map->keys[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
      stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) (map->values[i]), strlen (map->values[i]));
      if (yajl_gen_status_ok != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }

  stat = yajl_gen_map_close ((yajl_gen) g);
  if (yajl_gen_status_ok != stat)
    GEN_SET_ERROR_AND_RETURN (stat, err);
  if (! len && ! (ptx->options & OPT_GEN_SIMPLIFY))
    yajl_gen_config (g, yajl_gen_beautify, 1);
  return yajl_gen_status_ok;
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
make_json_map_string_string (yajl_val src, const struct parser_context *ctx,
                                                         parser_error *err)
{
  __auto_cleanup (free_json_map_string_string) json_map_string_string *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */
  if (src == NULL || YAJL_GET_OBJECT (src) == NULL)
    return NULL;

  len = YAJL_GET_OBJECT_NO_CHECK (src)->len;

  ret = calloc (sizeof (*ret), 1);
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
  for (i = 0; i < len; i++)
    {
      const char *srckey = YAJL_GET_OBJECT_NO_CHECK (src)->keys[i];
      yajl_val srcval = YAJL_GET_OBJECT_NO_CHECK (src)->values[i];

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
          char *str;
          if (! YAJL_IS_STRING (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'string' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }

          str = YAJL_GET_STRING_NO_CHECK (srcval);

          ret->values[i] = strdup (str ? str : "");
          if (ret->values[i] == NULL)
            {
              return NULL;
            }
        }
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

  ret = calloc (sizeof (*ret), 1);
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

static void
cleanup_yajl_gen (yajl_gen g)
{
  if (! g)
    return;
  yajl_gen_clear (g);
  yajl_gen_free (g);
}

define_cleaner_function (yajl_gen, cleanup_yajl_gen)

char *
json_marshal_string (const char *str, size_t length, const struct parser_context *ctx, parser_error *err)
{
  __auto_cleanup (cleanup_yajl_gen) yajl_gen g = NULL;
  struct parser_context tmp_ctx = { 0 };
  const unsigned char *gen_buf = NULL;
  char *json_buf = NULL;
  size_t gen_len = 0;
  yajl_gen_status stat;

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
  stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *) str, length);
  if (yajl_gen_status_ok != stat)
    {
      if (asprintf (err, "error generating json, errcode: %d", (int) stat) < 0)
        *err = strdup ("error allocating memory");
      return json_buf;
    }
  yajl_gen_get_buf (g, &gen_buf, &gen_len);
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
