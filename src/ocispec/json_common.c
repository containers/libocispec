#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "ocispec/json_common.h"

#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
#define YAJL_GET_STRING_NO_CHECK(v) ((v)->u.string)

#define MAX_NUM_STR_LEN 21

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

/*
* This function converts double to int
* Input: double d, int *converted
* Ouput: int
*/
int
json_double_to_int (double d, int *converted)
{
  long long int lli;
  lli = (long long int) d;

  if (lli > INT_MAX || lli < INT_MIN)
    return -ERANGE;

  *converted = (int) lli;
  return 0;
}

/*
* This function converts double to int64
* Input: double d, int64 *converted
* Ouput: int
*/
int
json_double_to_int64 (double d, int64_t *converted)
{
  long long int lli;
  lli = (long long int) d;
  *converted = (int64_t) lli;
  return 0;
}

/*
* This function converts double to int32
* Input: double d, int32 *converted
* Ouput: int
*/
int
json_double_to_int32 (double d, int32_t *converted)
{
  long long int lli;
  lli = (long long int) d;

  if (lli > INT32_MAX || lli < INT32_MIN)
    return -ERANGE;

  *converted = (int32_t) lli;
  return 0;
}

/*
* This function converts double to int16
* Input: double d, int16 *converted
* Ouput: int
*/
int
json_double_to_int16 (double d, int16_t *converted)
{
  long int li;
  li = (long int) d;
  if (li > INT16_MAX || li < INT16_MIN)
    return -ERANGE;

  *converted = (int16_t) li;
  return 0;
}

/*
* This function converts double to int8
* Input: double d, int8 *converted
* Ouput: int
*/
int
json_double_to_int8 (double d, int8_t *converted)
{
  long int li;
  li = (long int) d;
  if (li > INT8_MAX || li < INT8_MIN)
    return -ERANGE;
  *converted = (int8_t) li;
  return 0;
}

/*
* This function converts double to uint
* Input: double d, unsigned int *converted
* Ouput: int
*/
int
json_double_to_uint (double d, unsigned int *converted)
{
  unsigned long long int ull;
  ull = (unsigned long long int) d;

  if (ull > UINT_MAX)
    return -ERANGE;

  *converted = (unsigned int) ull;
  return 0;
}

/*
* This function converts double to uint64
* Input: double d, uint64_t *converted
* Ouput: int
*/
int
json_double_to_uint64 (double d, uint64_t *converted)
{
  unsigned long long int ull;
  ull = (unsigned long long int) d;
  *converted = (uint64_t) ull;
  return 0;
}

/*
* This function converts double to uint32
* Input: double d, uint32_t *converted
* Ouput: int
*/
int
json_double_to_uint32 (double d, uint32_t *converted)
{
  unsigned long long int ull;
  ull = (unsigned long long int) d;

  if (ull > UINT32_MAX)
    return -ERANGE;

  *converted = (uint32_t) ull;
  return 0;
}

/*
* This function converts double to uint16
* Input: double d, uint16_t *converted
* Ouput: int
*/
int
json_double_to_uint16 (double d, uint16_t *converted)
{
  unsigned long int uli;
  uli = (unsigned long int) d;
  if (uli > UINT16_MAX)
    return -ERANGE;

  *converted = (uint16_t) uli;
  return 0;
}

/*
* This function converts double to uint8
* Input: double d, uint8_t *converted
* Ouput: int
*/
int
json_double_to_uint8 (double d, uint8_t *converted)
{
  unsigned long int uli;
  uli = (unsigned long int) d;
  
  if (uli > UINT8_MAX)
    return -ERANGE;

  *converted = (uint8_t) uli;
  return 0;
}

/*
* This function converts double to double, kind of silly :)
* Input: double d, double *converted
* Ouput: int
*/
int
json_double_to_double (double d, double *converted)
{
  *converted = d;
  return 0;
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

int
gen_json_map_string_string (json_t *root, const json_map_string_string *map, parser_error *err)
{
  int stat = JSON_GEN_SUCCESS;
  size_t len = 0, i = 0;
  if (map != NULL)
    len = map->len;
  
  for (i = 0; i < len; i++)
    {
      stat = json_object_set(root, (const char *)(map->keys[i]), json_string((const char *)(map->values[i])));
      if (JSON_GEN_SUCCESS != stat)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    }
  return JSON_GEN_SUCCESS;
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
make_json_map_string_string (json_t *src, const struct parser_context *ctx,
                                                         parser_error *err)
{
  __auto_cleanup (free_json_map_string_string) json_map_string_string *ret = NULL;
  size_t i;
  size_t len;

  (void) ctx; /* Silence compiler warning.  */
  if (src == NULL)
    return NULL;

  
  len = json_object_to_keys_values (src)->len;

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
  for (i = 0; i < len; i++)
    {
      const char *srckey = json_object_to_keys_values (src)->keys[i];
      const json_t *srcval = &json_object_to_keys_values (src)->values[i];

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
          if (! json_is_string (srcval))
            {
              if (*err == NULL && asprintf (err, "Invalid value with type 'string' for key '%s'", srckey) < 0)
                {
                  *err = strdup ("error allocating memory");
                }
              return NULL;
            }

          str = json_string_value(srcval);

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


/**
 * json_array_to_struct This function extracts keys and values and stores it in struct
 * Input: json_t
 * Output: jansson_array_values *
 */
jansson_array_values *json_array_to_struct(json_t *array) {
    if (!json_is_array(array)) {
        // Handle error: Input is not an array
        return NULL;
    }

    size_t len = json_array_size(array);
    jansson_array_values *result = malloc(sizeof(jansson_array_values));
    if (!result) {
        return NULL; // Handle allocation failure
    }

    result->values = json_array();
    result->len = len;

    if (!result->values) {
        free(result);
        return NULL; // Handle allocation failure
    }

    for (size_t i = 0; i < len; i++) {
        json_t *value = json_array_get(array, i);
        json_array_append_new(result->values, json_incref(value));
    }

    return result;
}


/**
 * json_object_to_keys_values This function extracts keys and values and stores it in array of keys and values
 * Input: json_t
 * Output: jansson_object_keys_values *
 */
jansson_object_keys_values *json_object_to_keys_values(json_t *object) {
    if (!json_is_object(object)) {
        // Handle error: Input is not an object
        return NULL;
    }

    size_t len = json_object_size(object);
    jansson_object_keys_values *result = malloc(sizeof(jansson_object_keys_values));
    if (!result) {
        return NULL; // Handle allocation failure
    }

    result->keys = calloc(len, sizeof(char*));
    result->values = json_array();
    result->len = len;

    if (!result->keys || !result->values) {
        free(result->keys);
        json_decref(result->values);
        free(result);
        return NULL; // Handle allocation failure
    }

    json_t *key_iter = json_object_iter(object);
    for (size_t i = 0; key_iter; key_iter = json_object_iter_next(object, key_iter)) {
        const char *key = json_object_iter_key(key_iter);
        json_t *value = json_object_iter_value(key_iter);

        result->keys[i] = strdup(key);
        json_array_append_new(result->values, json_incref(value));
        i++;
    }

    return result;
}


/**
 * copy_unmatched_fields We extract all the fields and we match them with the supplied keys if they don't match
 * we add it to new json_t
 * Input: json_t, const char **, size_t
 * Ouput: jsont_t
 */
json_t *copy_unmatched_fields(json_t *src, const char **exclude_keys, size_t num_keys) {
    json_t *dst = json_object();
    json_t *value;

    json_t *key_iter = json_object_iter(src);
    while (key_iter) {
        const char *key = json_object_iter_key(key_iter);
        value = json_object_iter_value(key_iter);

        bool found = false;
        for (size_t i = 0; i < num_keys; i++) {
            if (strcmp(key, exclude_keys[i]) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            json_object_set_new(dst, key, json_incref(value));
        }

        key_iter = json_object_iter_next(src, key_iter);
    }

    return dst;
}