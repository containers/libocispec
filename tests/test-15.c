/* Copyright (C) 2026 Giuseppe Scrivano <giuseppe@scrivano.org>

libocispec is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

libocispec is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libocispec.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "ocispec/basic_test_int64_values.h"

#define CHECK_INT64(field, expected) do { \
    if (data->field != (expected)) { \
      printf (#field ": expected %" PRId64 ", got %" PRId64 "\n", (int64_t)(expected), data->field); \
      exit (1); \
    } \
  } while (0)

#define CHECK_UINT64(field, expected) do { \
    if (data->field != (expected)) { \
      printf (#field ": expected %" PRIu64 ", got %" PRIu64 "\n", (uint64_t)(expected), data->field); \
      exit (1); \
    } \
  } while (0)

#define CHECK_ROUNDTRIP_INT64(field) do { \
    if (data2->field != data->field) { \
      printf ("round-trip " #field ": expected %" PRId64 ", got %" PRId64 "\n", data->field, data2->field); \
      exit (1); \
    } \
  } while (0)

#define CHECK_ROUNDTRIP_UINT64(field) do { \
    if (data2->field != data->field) { \
      printf ("round-trip " #field ": expected %" PRIu64 ", got %" PRIu64 "\n", data->field, data2->field); \
      exit (1); \
    } \
  } while (0)

int
main ()
{
  parser_error err = NULL;
  struct parser_context ctx = { 0 };
  basic_test_int64_values *data;
  basic_test_int64_values *data2;
  char *json_buf = NULL;

  data = basic_test_int64_values_parse_file ("tests/data/int64_values.json", &ctx, &err);
  if (data == NULL)
    {
      printf ("parse error: %s\n", err);
      free (err);
      return 1;
    }

  /* int64 checks.  */
  CHECK_INT64 (positive_int64, 5000000000000000000LL);
  CHECK_INT64 (negative_int64, -5000000000000000000LL);
  CHECK_INT64 (max_int64, INT64_MAX);
  CHECK_INT64 (min_int64, INT64_MIN);
  CHECK_INT64 (zero_int64, 0);
  CHECK_INT64 (max_int64_minus1, INT64_MAX - 1);
  CHECK_INT64 (min_int64_plus1, INT64_MIN + 1);
  CHECK_INT64 (one_int64, 1);
  CHECK_INT64 (neg_one_int64, -1);
  CHECK_INT64 (neg_two_int64, -2);

  /* uint64 checks.  */
  CHECK_UINT64 (small_uint64, 42);
  CHECK_UINT64 (large_uint64, 10000000000000000000ULL);
  CHECK_UINT64 (max_uint64, UINT64_MAX);
  CHECK_UINT64 (max_uint64_minus1, UINT64_MAX - 1);
  CHECK_UINT64 (zero_uint64, 0);
  CHECK_UINT64 (one_uint64, 1);

  /* Round-trip: generate JSON, re-parse, and verify.  */
  json_buf = basic_test_int64_values_generate_json (data, &ctx, &err);
  if (json_buf == NULL)
    {
      printf ("generate error: %s\n", err);
      free (err);
      exit (1);
    }

  data2 = basic_test_int64_values_parse_data (json_buf, &ctx, &err);
  if (data2 == NULL)
    {
      printf ("re-parse error: %s\n", err);
      free (err);
      exit (1);
    }

  CHECK_ROUNDTRIP_INT64 (positive_int64);
  CHECK_ROUNDTRIP_INT64 (negative_int64);
  CHECK_ROUNDTRIP_INT64 (max_int64);
  CHECK_ROUNDTRIP_INT64 (min_int64);
  CHECK_ROUNDTRIP_INT64 (zero_int64);
  CHECK_ROUNDTRIP_INT64 (max_int64_minus1);
  CHECK_ROUNDTRIP_INT64 (min_int64_plus1);
  CHECK_ROUNDTRIP_INT64 (one_int64);
  CHECK_ROUNDTRIP_INT64 (neg_one_int64);
  CHECK_ROUNDTRIP_INT64 (neg_two_int64);

  CHECK_ROUNDTRIP_UINT64 (small_uint64);
  CHECK_ROUNDTRIP_UINT64 (large_uint64);
  CHECK_ROUNDTRIP_UINT64 (max_uint64);
  CHECK_ROUNDTRIP_UINT64 (max_uint64_minus1);
  CHECK_ROUNDTRIP_UINT64 (zero_uint64);
  CHECK_ROUNDTRIP_UINT64 (one_uint64);

  free (json_buf);
  free_basic_test_int64_values (data);
  free_basic_test_int64_values (data2);

  return 0;
}
