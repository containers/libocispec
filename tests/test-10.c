/* Copyright (C) 2020 duguhaotian <knowledgehao@163.com>

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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ocispec/basic_test_double_array.h"
#include "ocispec/basic_test_top_array_int.h"
#include "ocispec/basic_test_top_array_string.h"
#include "ocispec/basic_test_top_double_array_int.h"
#include "ocispec/basic_test_top_double_array_obj.h"
#include "ocispec/basic_test_top_double_array_string.h"
#include "ocispec/basic_test_top_double_array_refobj.h"

int
do_test_object_double_array()
{
  parser_error err = NULL;
  struct parser_context ctx = { 0 };
  int ret = 0;

  basic_test_double_array *test_data = basic_test_double_array_parse_file(
          "tests/data/doublearray.json", &ctx, &err);
  char *json_buf = NULL;
  size_t i, j;

  if (test_data == NULL) {
    printf ("error %s\n", err);
    free(err);
    return 1;
  }

  // check double array of string
  if (test_data->strarrays_len != 3) {
      printf("invalid strarrays len\n");
      ret = 1;
      goto out;
  }
  char *expect_strs[3][4] = {
      {"stra", "strb", "strc", NULL},
      {"str2a", "str2b", NULL},
      {"str3a", NULL},
  };
  size_t str_lens[3] = {3, 2, 1};

  for (i = 0; i < 3; i++) {
      if (test_data->strarrays[i] == NULL || test_data->strarrays_item_lens == NULL) {
        printf("item %zu is null\n", i);
        ret = 1;
        goto out;
      }
      if (test_data->strarrays_item_lens[i] != str_lens[i]) {
        printf("double array str item %zu is expect len: %zu, get: %zu\n", i, str_lens[i], test_data->strarrays_item_lens[i]);
        ret = 1;
        goto out;
      }
      for (j = 0; j < 4 && expect_strs[i][j] != NULL; j++) {
          if (test_data->strarrays[i][j] == NULL || strcmp(test_data->strarrays[i][j], expect_strs[i][j]) != 0) {
              printf("item %zu: expect: %s, get: %s\n", i, expect_strs[i][j], test_data->strarrays[i][j]);
              ret = 1;
              goto out;
          }
      }
  }
  // check double array of int32
  if (test_data->intarrays_len != 3) {
      printf("invalid intarrays len\n");
      ret = 1;
      goto out;
  }
  int32_t expect_ints[3][4] = {
      {1},
      {1, 2},
      {1, 2, 3},
      };
  size_t int_lens[3] = {1, 2, 3};
  for (i = 0; i < 3; i++) {
      if (test_data->intarrays[i] == NULL || test_data->intarrays_item_lens == NULL) {
        printf("item %zu is null\n", i);
        ret = 1;
        goto out;
      }
      if (test_data->intarrays_item_lens[i] != int_lens[i]) {
        printf("double array int item %zu is expect len: %zu, get: %zu\n", i, int_lens[i], test_data->intarrays_item_lens[i]);
        ret = 1;
        goto out;
      }
      for (j = 0; j < 4 && expect_ints[i][j] != 0; j++) {
          if (test_data->intarrays[i][j] != expect_ints[i][j]) {
              printf("item %zu: expect: %d, get: %d\n", i, expect_ints[i][j], test_data->intarrays[i][j]);
              ret = 1;
              goto out;
          }
      }
  }

  // check bool array of int32
  if (test_data->boolarrays_len != 4) {
      printf("invalid bool arrays len\n");
      ret = 1;
      goto out;
  }
  int32_t expect_bools[4][2] = {
      {true, false},
      {false, true},
      {true},
      {false},
      };
  size_t bool_lens[4] = {2, 2, 1, 1};

  for (i = 0; i < 4; i++) {
      if (test_data->boolarrays[i] == NULL || test_data->boolarrays_item_lens == NULL) {
        printf("item %zu is null\n", i);
        ret = 1;
        goto out;
      }
      if (test_data->boolarrays_item_lens[i] != bool_lens[i]) {
        printf("double array bool item %zu is expect len: %zu, get: %zu\n", i, bool_lens[i], test_data->boolarrays_item_lens[i]);
        ret = 1;
        goto out;
      }
      for (j = 0; j < bool_lens[i]; j++) {
          if (test_data->boolarrays[i][j] != expect_bools[i][j]) {
              printf("item %zu: expect: %d, get: %d\n", i, expect_bools[i][j], test_data->boolarrays[i][j]);
              ret = 1;
              goto out;
          }
      }
  }


  // check object array of int32
  if (test_data->objectarrays_len != 2) {
      printf("invalid object arrays len\n");
      ret = 1;
      goto out;
  }
  bool obj_firsts[2][3] = {
      {true, false, true},
      {false, true, false},
  };
  char *obj_seconds[2][3] = {
      {"item1", "item2", "item3"},
      {"item11", "item12", "item13"},
  };
  for (i = 0; i < 2; i++) {
      if (test_data->objectarrays[i] == NULL || test_data->objectarrays_item_lens == NULL) {
        printf("object array item %zu: is null\n", i);
        ret = 1;
        goto out;
      }
      for (j = 0; j < 3; j++) {
          if (obj_firsts[i][j] != test_data->objectarrays[i][j]->first) {
              printf("item %zu -> %zu: expect: %d, get: %d\n", 
                      i, j, obj_firsts[i][j], test_data->objectarrays[i][j]->first);
              ret = 1;
              goto out;
          }
          if (test_data->objectarrays[i][j]->second == NULL || 
                  strcmp(obj_seconds[i][j], test_data->objectarrays[i][j]->second) != 0) {
              printf("item %zu -> %zu: expect: %s, get: %s\n", 
                      i, j, obj_seconds[i][j], test_data->objectarrays[i][j]->second);
              ret = 1;
              goto out;
          }
      }
  }

  // check ref object array of int32
  if (test_data->refobjarrays_len != 2) {
      printf("invalid ref object arrays len\n");
      ret = 1;
      goto out;
  }
  char *refobj_item1[2][3] = {
      {"first1", "first2", "first3"},
      {"second1", "second2", "second3"},
  };
  int32_t refobj_item2[2][3] = {
      {1, 2, 3},
      {11, 12, 13},
  };
  bool refobj_item3[2][3] = {
      {false, true, false},
      {true, false, true},
  };
  for (i = 0; i < 2; i++) {
      if (test_data->refobjarrays[i] == NULL || test_data->refobjarrays_item_lens == NULL) {
        printf("object array item %zu: is null\n", i);
        ret = 1;
        goto out;
      }
      for (j = 0; j < 3; j++) {
          if (refobj_item3[i][j] != test_data->refobjarrays[i][j]->item3) {
              printf("item %zu -> %zu: expect: %d, get: %d\n", 
                      i, j, refobj_item3[i][j], test_data->refobjarrays[i][j]->item3);
              ret = 1;
              goto out;
          }
          if (refobj_item2[i][j] != test_data->refobjarrays[i][j]->item2) {
              printf("item %zu -> %zu: expect: %d, get: %d\n", 
                      i, j, refobj_item2[i][j], test_data->refobjarrays[i][j]->item2);
              ret = 1;
              goto out;
          }
          if (test_data->refobjarrays[i][j]->item1 == NULL || 
                  strcmp(refobj_item1[i][j], test_data->refobjarrays[i][j]->item1) != 0) {
              printf("item %zu -> %zu: expect: %s, get: %s\n", 
                      i, j, refobj_item1[i][j], test_data->refobjarrays[i][j]->item1);
              ret = 1;
              goto out;
          }
      }
  }
  printf("double array of object check parse sucess\n");

  // update test data, and check generate json
  free(test_data->strarrays[0][0]);
  test_data->strarrays[0][0] = strdup("stringtestflag");
  test_data->intarrays[0][0] = 8888;
  free(test_data->objectarrays[0][0]->second);
  test_data->objectarrays[0][0]->second = strdup("objectteststr");
  free(test_data->refobjarrays[0][0]->item1);
  test_data->refobjarrays[0][0]->item1 = strdup("objectrefstr");
  
  json_buf = basic_test_double_array_generate_json(test_data, &ctx, &err);
  if (json_buf == NULL) {
    printf("gen error %s\n", err);
    ret = 1;
    goto out;
  }

  printf("%s\n", json_buf);

  // origin json str should same with generate new json str,
  if (strstr(json_buf, "stringtestflag") == NULL)
  {
      ret = 51;
      goto out;
  }
  if (strstr(json_buf, "objectteststr") == NULL)
  {
      ret = 52;
      goto out;
  }
  if (strstr(json_buf, "objectrefstr") == NULL)
  {
      ret = 53;
      goto out;
  }
  if (strstr(json_buf, "8888") == NULL)
  {
      ret = 54;
      goto out;
  }

out:
  free(err);
  free(json_buf);
  free_basic_test_double_array(test_data);
  return ret;
}

int do_test_top_array_of_int()
{
  parser_error err = NULL;
  struct parser_context ctx = { 0 };
  int ret = 0;

  basic_test_top_array_int_container *test_data = basic_test_top_array_int_container_parse_file(
          "tests/data/top_array_int.json", &ctx, &err);
  char *json_buf = NULL;

  if (test_data == NULL)
  {
    printf("top int array parse error %s\n", err);
    free(err);
    return 1;
  }
  size_t i;
  uint8_t expect[3] = {1, 2, 3};
  if (test_data->len != 3)
  {
    printf("top int array expect len: 3, get: %zu\n", test_data->len);
    ret = 1;
    goto out;
  }

  for (i = 0; i < 3; i++)
  {
      if (test_data->items[i] != expect[i])
      {
        printf("item %zu: top int array expect: %u, get: %u\n", i, expect[i], test_data->items[i]);
        ret = 1;
        goto out;
      }
  }
  test_data->items[0] = 111;
  json_buf = basic_test_top_array_int_container_generate_json(test_data, &ctx, &err);
  if (json_buf == NULL)
  {
    printf("gen error %s\n", err);
    ret = 1;
    goto out;
  }
  if (strstr(json_buf, "111") == NULL)
  {
    printf("change not work %s\n", err);
    ret = 1;
    goto out;
  }

out:
  free(err);
  free_basic_test_top_array_int_container(test_data);
  free(json_buf);
  return ret;
}

int do_test_top_array_of_string()
{
  parser_error err = NULL;
  struct parser_context ctx = { 0 };
  int ret = 0;

  basic_test_top_array_string_container *test_data = basic_test_top_array_string_container_parse_file(
          "tests/data/top_array_string.json", &ctx, &err);
  char *json_buf = NULL;

  if (test_data == NULL)
  {
    printf("top int array parse error %s\n", err);
    free(err);
    return 1;
  }
  size_t i;
  char *expect[3] = {"topstr1", "topstr2"};
  if (test_data->len != 2)
  {
    printf("top int array expect len: 3, get: %zu\n", test_data->len);
    ret = 1;
    goto out;
  }

  for (i = 0; i < 2; i++)
  {
      if (test_data->items[i] == NULL || strcmp(test_data->items[i], expect[i]) != 0)
      {
        printf("item %zu: top int array expect: %s, get: %s\n", i, expect[i], test_data->items[i]);
        ret = 1;
        goto out;
      }
  }
  free(test_data->items[0]);
  test_data->items[0] = strdup("hello");
  json_buf = basic_test_top_array_string_container_generate_json(test_data, &ctx, &err);
  if (json_buf == NULL)
  {
    printf("gen error %s\n", err);
    ret = 1;
    goto out;
  }
  if (strstr(json_buf, "hello") == NULL)
  {
    printf("change not work %s\n", err);
    ret = 1;
    goto out;
  }

out:
  free(err);
  free_basic_test_top_array_string_container(test_data);
  free(json_buf);
  return ret;
}

int do_test_top_double_array_of_string()
{
  parser_error err = NULL;
  struct parser_context ctx = { 0 };
  int ret = 0;

  basic_test_top_double_array_string_container *test_data = basic_test_top_double_array_string_container_parse_file(
          "tests/data/top_double_array_string.json", &ctx, &err);
  char *json_buf = NULL;

  if (test_data == NULL)
  {
    printf("top string double array parse error %s\n", err);
    free(err);
    return 1;
  }
  size_t i;
  char *expect[3][2] = {{"doublestr11"}, {"doublestr21", "doublestr22"}, {"doublestr31", "doublestr32"}};
  size_t expect_lens[3] = {1, 2, 2};
  if (test_data->len != 3)
  {
    printf("top string double array expect len: 3, get: %zu\n", test_data->len);
    ret = 1;
    goto out;
  }

  for (i = 0; i < 3; i++)
  {
      size_t j;
      if (test_data->subitem_lens[i] != expect_lens[i])
      {
        printf("item %zu: top string double array expect len: %zu, get: %zu\n", i, expect_lens[i], test_data->subitem_lens[i]);
        ret = 1;
        goto out;
      }
      for (j = 0; j < expect_lens[i]; j++)
      {
          if (test_data->items[i][j] == NULL || strcmp(test_data->items[i][j], expect[i][j]) != 0)
          {
            printf("item %zu: top int array expect: %s, get: %s\n", i, expect[i][j], test_data->items[i][j]);
            ret = 1;
            goto out;
          }
      }
  }
  free(test_data->items[0][0]);
  test_data->items[0][0] = strdup("hello");
  json_buf = basic_test_top_double_array_string_container_generate_json(test_data, &ctx, &err);
  if (json_buf == NULL)
  {
    printf("gen error %s\n", err);
    ret = 1;
    goto out;
  }
  if (strstr(json_buf, "hello") == NULL)
  {
    printf("change not work %s\n", err);
    ret = 1;
    goto out;
  }

out:
  free_basic_test_top_double_array_string_container(test_data);
  free(err);
  free(json_buf);
  return ret;
}

int do_test_top_double_array_of_int()
{
  parser_error err = NULL;
  struct parser_context ctx = { 0 };
  int ret = 0;

  basic_test_top_double_array_int_container *test_data = basic_test_top_double_array_int_container_parse_file(
          "tests/data/top_double_array_int.json", &ctx, &err);
  char *json_buf = NULL;

  if (test_data == NULL)
  {
    printf("top int double array parse error %s\n", err);
    free(err);
    return 1;
  }
  size_t i;
  int32_t expect[3][3] = {{1, 2, 3}, {1, 2}, {1}};
  size_t expect_lens[3] = {3, 2, 1};
  if (test_data->len != 3)
  {
    printf("top int double array expect len: 3, get: %zu\n", test_data->len);
    ret = 1;
    goto out;
  }

  for (i = 0; i < 3; i++)
  {
      size_t j;
      if (test_data->subitem_lens[i] != expect_lens[i])
      {
        printf("item %zu: top int double array expect len: %zu, get: %zu\n", i, expect_lens[i], test_data->subitem_lens[i]);
        ret = 1;
        goto out;
      }
      for (j = 0; j < expect_lens[i]; j++)
      {
          if (test_data->items[i][j] != expect[i][j])
          {
            printf("item %zu: top int array expect: %d, get: %d\n", i, expect[i][j], test_data->items[i][j]);
            ret = 1;
            goto out;
          }
      }
  }
  test_data->items[0][0] = 888;
  json_buf = basic_test_top_double_array_int_container_generate_json(test_data, &ctx, &err);
  if (json_buf == NULL)
  {
    printf("gen error %s\n", err);
    ret = 1;
    goto out;
  }
  if (strstr(json_buf, "888") == NULL)
  {
    printf("change not work %s\n", err);
    ret = 1;
    goto out;
  }

out:
  free(err);
  free_basic_test_top_double_array_int_container(test_data);
  free(json_buf);
  return ret;
}

int do_test_top_double_array_of_obj()
{
  parser_error err = NULL;
  struct parser_context ctx = { 0 };
  int ret = 0;

  basic_test_top_double_array_obj_container *test_data = basic_test_top_double_array_obj_container_parse_file(
          "tests/data/top_double_array_obj.json", &ctx, &err);
  char *json_buf = NULL;

  if (test_data == NULL)
  {
    printf("top int double array parse error %s\n", err);
    free(err);
    return 1;
  }
  size_t i;
  bool expect_bools[2][2] = {{true, false}, {false, true}};
  int32_t expect_ints[2][2] = {{11, 12}, {21, 22}};
  char *expect_strs[2][2] = {{"doubleobj11", "doubleobj12"}, {"doubleobj21", "doubleobj22"}};
  size_t expect_lens[3] = {2, 2};
  if (test_data->len != 2)
  {
    printf("top obj double array expect len: 2, get: %zu\n", test_data->len);
    ret = 1;
    goto out;
  }

  for (i = 0; i < 2; i++)
  {
      size_t j;
      if (test_data->subitem_lens[i] != expect_lens[i])
      {
        printf("item %zu: top obj double array expect len: %zu, get: %zu\n", i, expect_lens[i], test_data->subitem_lens[i]);
        ret = 1;
        goto out;
      }
      for (j = 0; j < expect_lens[i]; j++)
      {
          if (test_data->items[i][j]->first != expect_bools[i][j])
          {
            printf("item %zu: top int array first expect: %d, get: %d\n", i, expect_bools[i][j], test_data->items[i][j]->first);
            ret = 1;
            goto out;
          }
          if (test_data->items[i][j]->second != expect_ints[i][j])
          {
            printf("item %zu: top int array second expect: %d, get: %d\n", i, expect_ints[i][j], test_data->items[i][j]->second);
            ret = 1;
            goto out;
          }
          if (test_data->items[i][j]->third == NULL || strcmp(test_data->items[i][j]->third, expect_strs[i][j]) != 0)
          {
            printf("item %zu: top int array third expect: %s, get: %s\n", i, expect_strs[i][j], test_data->items[i][j]->third);
            ret = 1;
            goto out;
          }
      }
  }
  test_data->items[0][0]->second = 999;
  free(test_data->items[0][1]->third);
  test_data->items[0][1]->third = strdup("hello");
  json_buf = basic_test_top_double_array_obj_container_generate_json(test_data, &ctx, &err);
  if (json_buf == NULL)
  {
    printf("gen error %s\n", err);
    ret = 1;
    goto out;
  }
  if (strstr(json_buf, "999") == NULL)
  {
    printf("change second not work %s\n", err);
    ret = 1;
    goto out;
  }
  if (strstr(json_buf, "hello") == NULL)
  {
    printf("change third not work %s\n", err);
    ret = 1;
    goto out;
  }

out:
  free(err);
  free_basic_test_top_double_array_obj_container(test_data);
  free(json_buf);
  return ret;
}

int do_test_top_double_array_of_refobj()
{
  parser_error err = NULL;
  struct parser_context ctx = { 0 };
  int ret = 0;

  basic_test_top_double_array_refobj_container *test_data = basic_test_top_double_array_refobj_container_parse_file(
          "tests/data/top_double_array_refobj.json", &ctx, &err);
  char *json_buf = NULL;

  if (test_data == NULL)
  {
    printf("top int double array parse error %s\n", err);
    free(err);
    return 1;
  }
  size_t i;
  bool expect_bools[2][2] = {{true, false}, {false, true}};
  int32_t expect_ints[2][2] = {{11, 12}, {21, 22}};
  char *expect_strs[2][2] = {{"test11", "test12"}, {"test21", "test22"}};
  size_t expect_lens[3] = {2, 2};
  if (test_data->len != 2)
  {
    printf("top obj double array expect len: 2, get: %zu\n", test_data->len);
    ret = 1;
    goto out;
  }

  for (i = 0; i < 2; i++)
  {
      size_t j;
      if (test_data->subitem_lens[i] != expect_lens[i])
      {
        printf("item %zu: top obj double array expect len: %zu, get: %zu\n", i, expect_lens[i], test_data->subitem_lens[i]);
        ret = 1;
        goto out;
      }
      for (j = 0; j < expect_lens[i]; j++)
      {
          if (test_data->items[i][j]->item3 != expect_bools[i][j])
          {
            printf("item %zu: top int array first expect: %d, get: %d\n", i, expect_bools[i][j], test_data->items[i][j]->item3);
            ret = 1;
            goto out;
          }
          if (test_data->items[i][j]->item2 != expect_ints[i][j])
          {
            printf("item %zu: top int array second expect: %d, get: %d\n", i, expect_ints[i][j], test_data->items[i][j]->item2);
            ret = 1;
            goto out;
          }
          if (test_data->items[i][j]->item1 == NULL || strcmp(test_data->items[i][j]->item1, expect_strs[i][j]) != 0)
          {
            printf("item %zu: top int array third expect: %s, get: %s\n", i, expect_strs[i][j], test_data->items[i][j]->item1);
            ret = 1;
            goto out;
          }
      }
  }
  test_data->items[0][0]->item2 = 999;
  free(test_data->items[0][1]->item1);
  test_data->items[0][1]->item1 = strdup("hello");
  json_buf = basic_test_top_double_array_refobj_container_generate_json(test_data, &ctx, &err);
  if (json_buf == NULL)
  {
    printf("gen error %s\n", err);
    ret = 1;
    goto out;
  }
  if (strstr(json_buf, "999") == NULL)
  {
    printf("change second not work %s\n", err);
    ret = 1;
    goto out;
  }
  if (strstr(json_buf, "hello") == NULL)
  {
    printf("change third not work %s\n", err);
    ret = 1;
    goto out;
  }

out:
  free(err);
  free_basic_test_top_double_array_refobj_container(test_data);
  free(json_buf);
  return ret;
}

int
main ()
{
    int ret;

    ret = do_test_object_double_array();
    if (ret != 0) {
        printf("do_test_object_double_array failed with: %d\n", ret);
        exit(ret);
    }

    ret = do_test_top_array_of_int();
    if (ret != 0) {
        printf("do_test_top_array_of_int failed with: %d\n", ret);
        exit(ret);
    }
    ret = do_test_top_array_of_string();
    if (ret != 0) {
        printf("do_test_top_array_of_string failed with: %d\n", ret);
        exit(ret);
    }

    ret = do_test_top_double_array_of_string();
    if (ret != 0) {
        printf("do_test_top_double_array_of_string failed with: %d\n", ret);
        exit(ret);
    }
    ret = do_test_top_double_array_of_int();
    if (ret != 0) {
        printf("do_test_top_double_array_of_int failed with: %d\n", ret);
        exit(ret);
    }
    ret = do_test_top_double_array_of_obj();
    if (ret != 0) {
        printf("do_test_top_double_array_of_obj failed with: %d\n", ret);
        exit(ret);
    }
    ret = do_test_top_double_array_of_refobj();
    if (ret != 0) {
        printf("do_test_top_double_array_of_refobj failed with: %d\n", ret);
        exit(ret);
    }

    return 0;
}
