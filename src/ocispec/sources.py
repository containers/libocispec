# -*- coding: utf-8 -*-
#
# libocispec - a C library for parsing OCI spec files.
#
# Copyright (C) Huawei Technologies., Ltd. 2018-2020.
# Copyright (C) 2017, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
#
# libocispec is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# libocispec is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libocispec.  If not, see <http://www.gnu.org/licenses/>.
#
# As a special exception, you may create a larger work that contains
# part or all of the libocispec parser skeleton and distribute that work
# under terms of your choice, so long as that work isn't itself a
# parser generator using the skeleton or a modified version thereof
# as a parser skeleton.  Alternatively, if you modify or redistribute
# the parser skeleton itself, you may (at your option) remove this
# special exception, which will cause the skeleton and the resulting
# libocispec output files to be licensed under the GNU General Public
# License without this special exception.

from textwrap import dedent

import helpers


def emit(c_file, code, indent=0):
    """Emit code with proper indentation.

    Args:
        c_file: List to append code lines to
        code: Multi-line string (will be dedented)
        indent: Number of 4-space indentation levels
    """
    prefix = '    ' * indent
    for line in dedent(code).strip().split('\n'):
        if line:
            c_file.append(prefix + line + '\n')
        else:
            c_file.append('\n')


def free_and_null(c_file, ptr, field, indent=0):
    """Generate code to free a pointer and set it to NULL.

    Args:
        c_file: List to append code lines to
        ptr: Pointer variable name
        field: Field name (can include array indexing like '[i]')
        indent: Number of 4-space indentation levels
    """
    prefix = '    ' * indent
    c_file.append(f"{prefix}free ({ptr}->{field});\n")
    c_file.append(f"{prefix}{ptr}->{field} = NULL;\n")


def null_check_return(c_file, var, indent=0):
    """Generate NULL check with return NULL.

    Args:
        c_file: List to append code lines to
        var: Variable to check (can be expression like 'ret->field' or 'ret->field[i]')
        indent: Number of 4-space indentation levels
    """
    prefix = '    ' * indent
    c_file.append(f"{prefix}if ({var} == NULL)\n")
    c_file.append(f"{prefix}  return NULL;\n")


def calloc_with_check(c_file, dest, count, sizeof_expr, indent=0):
    """Generate calloc call with NULL check.

    Args:
        c_file: List to append code lines to
        dest: Destination variable
        count: Count expression for calloc
        sizeof_expr: sizeof expression (the content inside sizeof())
        indent: Number of 4-space indentation levels
    """
    prefix = '    ' * indent
    c_file.append(f"{prefix}{dest} = calloc ({count}, sizeof ({sizeof_expr}));\n")
    c_file.append(f"{prefix}if ({dest} == NULL)\n")
    c_file.append(f"{prefix}  return NULL;\n")


def check_gen_status(c_file, indent=0):
    """Generate yajl_gen status check with error return.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    prefix = '    ' * indent
    c_file.append(f"{prefix}if (stat != yajl_gen_status_ok)\n")
    c_file.append(f"{prefix}    GEN_SET_ERROR_AND_RETURN (stat, err);\n")


def do_read_value(c_file, src_expr, dest_expr, typ, origname, obj_typename, indent=1):
    """Wrap read_val_generator in a do-while(0) block.

    Args:
        c_file: Output file list
        src_expr: Source expression (e.g., 'get_val (tree, "name", yajl_t_string)')
        dest_expr: Destination expression (e.g., 'ret->field')
        typ: Field type
        origname: Original field name from schema
        obj_typename: Object type name
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        do
          {{
    ''', indent=indent)
    read_val_generator(c_file, indent + 1, src_expr, dest_expr, typ, origname, obj_typename)
    emit(c_file, f'''
          }}
        while (0);
    ''', indent=indent)


def emit_asprintf_error(c_file, err_var, format_str, format_args, indent=0):
    """Emit asprintf error with strdup fallback.

    Args:
        c_file: List to append code lines to
        err_var: Error variable (e.g., 'err' or '&new_error')
        format_str: Format string for asprintf
        format_args: Arguments for format string
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        if (asprintf ({err_var}, "{format_str}", {format_args}) < 0)
            *err = strdup ("error allocating memory");
    ''', indent=indent)


def emit_value_error(c_file, keyname, indent=0):
    """Emit value error handling with error message wrapping.

    Generates code to wrap an existing error message with additional context
    about which key failed to parse.

    Args:
        c_file: List to append code lines to
        keyname: The key name to include in the error message
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        char *new_error = NULL;
        if (asprintf (&new_error, "Value error for key '{keyname}': %s", *err ? *err : "null") < 0)
            new_error = strdup ("error allocating memory");
        free (*err);
        *err = new_error;
        return NULL;
    ''', indent=indent)


def emit_invalid_type_check(c_file, yajl_check='YAJL_IS_NUMBER', indent=0):
    """Emit YAJL type validation with error return.

    Args:
        c_file: List to append code lines to
        yajl_check: YAJL type check macro (e.g., 'YAJL_IS_NUMBER')
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        if (! {yajl_check} (val))
          {{
            *err = strdup ("invalid type");
            return NULL;
          }}
    ''', indent=indent)


def get_numeric_conversion_info(typ):
    """Get conversion function and cast for a numeric type.

    Args:
        typ: The type string (e.g., 'integer', 'uint64', 'UID')

    Returns:
        Tuple of (conversion_function, dest_cast) or None if not a numeric type
    """
    if typ.startswith("uint") or (typ.startswith("int") and typ != "integer") or typ == "double":
        return f'common_safe_{typ}', '&'
    elif typ == "integer":
        return 'common_safe_int', '(int *)&'
    elif typ == "UID" or typ == "GID":
        return 'common_safe_uint', '(unsigned int *)&'
    return None


# YAJL generation helpers

def emit_gen_key(c_file, key, indent=0):
    """Emit yajl_gen_string for an object key.

    Args:
        c_file: List to append code lines to
        key: Key string to generate
        indent: Number of 4-space indentation levels
    """
    key_len = len(key)
    emit(c_file, f'''
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{key}"), {key_len} /* strlen ("{key}") */);
    ''', indent=indent)


def emit_gen_map_open(c_file, indent=0):
    """Emit yajl_gen_map_open call.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    emit(c_file, '''
        stat = yajl_gen_map_open ((yajl_gen) g);
    ''', indent=indent)


def emit_gen_map_close(c_file, indent=0):
    """Emit yajl_gen_map_close call.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    emit(c_file, '''
        stat = yajl_gen_map_close ((yajl_gen) g);
    ''', indent=indent)


def emit_gen_array_open(c_file, indent=0):
    """Emit yajl_gen_array_open call.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    emit(c_file, '''
        stat = yajl_gen_array_open ((yajl_gen) g);
    ''', indent=indent)


def emit_gen_array_close(c_file, indent=0):
    """Emit yajl_gen_array_close call.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    emit(c_file, '''
        stat = yajl_gen_array_close ((yajl_gen) g);
    ''', indent=indent)


def emit_beautify_off(c_file, condition='!len', indent=0):
    """Emit yajl_gen_beautify disable.

    Args:
        c_file: List to append code lines to
        condition: Condition for disabling beautify
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        if ({condition} && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
    ''', indent=indent)


def emit_beautify_on(c_file, condition='!len', indent=0):
    """Emit yajl_gen_beautify enable.

    Args:
        c_file: List to append code lines to
        condition: Condition for enabling beautify
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        if ({condition} && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
    ''', indent=indent)


def append_c_code(obj, c_file, prefix):
    """
    Description: append c language code to file
    Interface: None
    History: 2019-06-17
    """
    parse_json_to_c(obj, c_file, prefix)
    make_c_free(obj, c_file, prefix)
    get_c_json(obj, c_file, prefix)
    make_clone(obj, c_file, prefix)

def parse_map_string_obj(obj, c_file, prefix, obj_typename):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    child = obj.children[0]
    if helpers.valid_basic_map_name(child.typ):
        childname = helpers.make_basic_map_name(child.typ)
    else:
        if child.subtypname:
            childname = child.subtypname
        else:
            childname = helpers.get_prefixed_name(child.name, prefix)

    emit(c_file, f'''
        if (YAJL_GET_OBJECT (tree) != NULL)
          {{
            size_t i;
            size_t len = YAJL_GET_OBJECT_NO_CHECK (tree)->len;
            const char **keys = YAJL_GET_OBJECT_NO_CHECK (tree)->keys;
            yajl_val *values = YAJL_GET_OBJECT_NO_CHECK (tree)->values;
            ret->len = len;
    ''', indent=1)

    calloc_with_check(c_file, 'ret->keys', 'len + 1', '*ret->keys', indent=2)
    calloc_with_check(c_file, f'ret->{child.fixname}', 'len + 1', f'*ret->{child.fixname}', indent=2)

    emit(c_file, f'''
            for (i = 0; i < len; i++)
              {{
                yajl_val val;
                const char *tmpkey = keys[i];
                ret->keys[i] = strdup (tmpkey ? tmpkey : "");
    ''', indent=2)

    null_check_return(c_file, 'ret->keys[i]', indent=3)

    emit(c_file, f'''
                val = values[i];
                ret->{child.fixname}[i] = make_{childname} (val, ctx, err);
    ''', indent=3)

    null_check_return(c_file, f'ret->{child.fixname}[i]', indent=3)

    c_file.append('          }\n')
    c_file.append('      }\n')


def parse_obj_type_array(obj, c_file, prefix, obj_typename):
    if obj.subtypobj or obj.subtyp == 'object':
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_name_substr(obj.name, prefix)

        emit(c_file, f'''
            do
              {{
                yajl_val tmp = get_val (tree, "{obj.origname}", yajl_t_array);
                if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
                  {{
                    size_t i;
                    size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
                    yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
                    ret->{obj.fixname}_len = len;
        ''', indent=1)

        calloc_with_check(c_file, f'ret->{obj.fixname}', 'len + 1', f'*ret->{obj.fixname}', indent=3)
        if obj.doublearray:
            calloc_with_check(c_file, f'ret->{obj.fixname}_item_lens', 'len + 1', 'size_t', indent=3)

        emit(c_file, '''
                    for (i = 0; i < len; i++)
                      {
                        yajl_val val = values[i];
        ''', indent=3)

        if obj.doublearray:
            emit(c_file, f'''
                        size_t j;
                        ret->{obj.fixname}[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(val)->len + 1, sizeof (**ret->{obj.fixname}));
            ''', indent=4)
            null_check_return(c_file, f'ret->{obj.fixname}[i]', indent=4)
            emit(c_file, '''
                        yajl_val *items = YAJL_GET_ARRAY_NO_CHECK(val)->values;
                        for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(val)->len; j++)
                          {
            ''', indent=4)
            emit(c_file, f'''
                            ret->{obj.fixname}[i][j] = make_{typename} (items[j], ctx, err);
            ''', indent=5)
            null_check_return(c_file, f'ret->{obj.fixname}[i][j]', indent=5)
            emit(c_file, f'''
                            ret->{obj.fixname}_item_lens[i] += 1;
                          }};
            ''', indent=5)
        else:
            emit(c_file, f'''
                        ret->{obj.fixname}[i] = make_{typename} (val, ctx, err);
            ''', indent=4)
            null_check_return(c_file, f'ret->{obj.fixname}[i]', indent=4)

        emit(c_file, '''
                          }
                    }
                  }
                while (0);
        ''', indent=1)
    elif obj.subtyp == 'byte':
        emit(c_file, f'''
            do
              {{
                yajl_val tmp = get_val (tree, "{obj.origname}", yajl_t_string);
                if (tmp != NULL)
                  {{
        ''', indent=1)

        if obj.doublearray:
            emit(c_file, f'''
                    yajl_val *items = YAJL_GET_ARRAY_NO_CHECK(tmp)->values;
                    ret->{obj.fixname} = calloc ( YAJL_GET_ARRAY_NO_CHECK(tmp)->len + 1, sizeof (*ret->{obj.fixname}));
            ''', indent=4)
            null_check_return(c_file, f'ret->{obj.fixname}[i]', indent=4)
            emit(c_file, '''
                    size_t j;
                    for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(tmp)->len; j++)
                      {
                        char *str = YAJL_GET_STRING (itmes[j]);
            ''', indent=4)
            emit(c_file, f'''
                        ret->{obj.fixname}[j] = (uint8_t *)strdup (str ? str : "");
            ''', indent=5)
            null_check_return(c_file, f'ret->{obj.fixname}[j]', indent=5)
            emit(c_file, '''
                      };
            ''', indent=5)
        else:
            emit(c_file, '''
                    char *str = YAJL_GET_STRING (tmp);
            ''', indent=3)
            emit(c_file, f'''
                    ret->{obj.fixname} = (uint8_t *)strdup (str ? str : "");
            ''', indent=3)
            null_check_return(c_file, f'ret->{obj.fixname}', indent=3)
            emit(c_file, f'''
                    ret->{obj.fixname}_len = str != NULL ? strlen (str) : 0;
            ''', indent=3)

        emit(c_file, '''
                    }
                  }
                while (0);
        ''', indent=1)
    else:
        emit(c_file, f'''
            do
              {{
                yajl_val tmp = get_val (tree, "{obj.origname}", yajl_t_array);
                if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
                  {{
                    size_t i;
                    size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
                    yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
                    ret->{obj.fixname}_len = len;
        ''', indent=1)

        calloc_with_check(c_file, f'ret->{obj.fixname}', 'len + 1', f'*ret->{obj.fixname}', indent=3)
        if obj.doublearray:
            calloc_with_check(c_file, f'ret->{obj.fixname}_item_lens', 'len + 1', 'size_t', indent=3)

        emit(c_file, '''
                    for (i = 0; i < len; i++)
                      {
        ''', indent=3)

        if obj.doublearray:
            emit(c_file, f'''
                        yajl_val *items = YAJL_GET_ARRAY_NO_CHECK(values[i])->values;
                        ret->{obj.fixname}[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(values[i])->len + 1, sizeof (**ret->{obj.fixname}));
            ''', indent=4)
            null_check_return(c_file, f'ret->{obj.fixname}[i]', indent=5)
            emit(c_file, '''
                        size_t j;
                        for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(values[i])->len; j++)
                          {
            ''', indent=4)
            read_val_generator(c_file, 5, 'items[j]', \
                                f"ret->{obj.fixname}[i][j]", obj.subtyp, obj.origname, obj_typename)
            emit(c_file, f'''
                            ret->{obj.fixname}_item_lens[i] += 1;
                        }};
            ''', indent=5)
        else:
            read_val_generator(c_file, 4, 'values[i]', \
                                f"ret->{obj.fixname}[i]", obj.subtyp, obj.origname, obj_typename)

        emit(c_file, '''
                          }
                    }
                  }
                while (0);
        ''', indent=1)

def parse_obj_type(obj, c_file, prefix, obj_typename):
    """
    Description: generate c language for parse object type
    Interface: None
    History: 2019-06-17
    """
    if obj.typ == 'string':
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", yajl_t_string)',
                      f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename, indent=1)
    elif helpers.judge_data_type(obj.typ):
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", yajl_t_number)',
                      f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename, indent=1)
    elif helpers.judge_data_pointer_type(obj.typ):
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", yajl_t_number)',
                      f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename, indent=1)
    if obj.typ == 'boolean':
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", yajl_t_true)',
                      f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename, indent=1)
    if obj.typ == 'booleanPointer':
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", yajl_t_true)',
                      f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename, indent=1)
    elif obj.typ == 'object' or obj.typ == 'mapStringObject':
        if obj.subtypname is not None:
            typename = obj.subtypname
        else:
            typename = helpers.get_prefixed_name(obj.name, prefix)
        emit(c_file, f'''
            ret->{obj.fixname} = make_{typename} (get_val (tree, "{obj.origname}", yajl_t_object), ctx, err);
            if (ret->{obj.fixname} == NULL && *err != 0)
              return NULL;
        ''', indent=1)
    elif obj.typ == 'array':
        parse_obj_type_array(obj, c_file, prefix, obj_typename)
    elif helpers.valid_basic_map_name(obj.typ):
        emit(c_file, f'''
            do
              {{
                yajl_val tmp = get_val (tree, "{obj.origname}", yajl_t_object);
                if (tmp != NULL)
                  {{
                    ret->{obj.fixname} = make_{helpers.make_basic_map_name(obj.typ)} (tmp, ctx, err);
                    if (ret->{obj.fixname} == NULL)
                      {{
        ''', indent=1)
        emit_value_error(c_file, obj.origname, indent=4)
        emit(c_file, '''
                      }
                  }
              }
            while (0);
        ''', indent=1)

def parse_obj_arr_obj(obj, c_file, prefix, obj_typename):
    """
    Description: generate c language for parse object or array object
    Interface: None
    History: 2019-06-17
    """
    nodes = obj.children if obj.typ == 'object' else obj.subtypobj
    required_to_check = []
    for i in nodes or []:
        if obj.required and i.origname in obj.required and \
                not helpers.judge_data_type(i.typ) and i.typ != 'boolean':
            required_to_check.append(i)
        parse_obj_type(i, c_file, prefix, obj_typename)

    for i in required_to_check:
        emit(c_file, f'''
            if (ret->{i.fixname} == NULL)
              {{
        ''', indent=1)
        emit_asprintf_error(c_file, 'err', "Required field '%s' not present", f'"{i.origname}"', indent=2)
        emit(c_file, '''
                return NULL;
              }
        ''', indent=1)

    if obj.typ == 'object' and obj.children is not None:
        # O(n^2) complexity, but the objects should not really be big...
        condition = "\n                && ".join( \
            [f'strcmp (tree->u.object.keys[i], "{i.origname}")' for i in obj.children])
        emit(c_file, f'''
            if (tree->type == yajl_t_object)
              {{
                size_t i;
                size_t j = 0;
                size_t cnt = tree->u.object.len;
                yajl_val resi = NULL;

                if (ctx->options & OPT_PARSE_FULLKEY)
                  {{
                    resi = calloc (1, sizeof(*tree));
                    if (resi == NULL)
                      return NULL;

                    resi->type = yajl_t_object;
                    resi->u.object.keys = calloc (cnt, sizeof (const char *));
                    if (resi->u.object.keys == NULL)
                      {{
                        yajl_tree_free (resi);
                        return NULL;
                      }}
                    resi->u.object.values = calloc (cnt, sizeof (yajl_val));
                    if (resi->u.object.values == NULL)
                      {{
                        yajl_tree_free (resi);
                        return NULL;
                      }}
                  }}

                for (i = 0; i < tree->u.object.len; i++)
                  {{
                    if ({condition}){{
                        if (ctx->options & OPT_PARSE_FULLKEY)
                          {{
                            resi->u.object.keys[j] = tree->u.object.keys[i];
                            tree->u.object.keys[i] = NULL;
                            resi->u.object.values[j] = tree->u.object.values[i];
                            tree->u.object.values[i] = NULL;
                            resi->u.object.len++;
                          }}
                        j++;
                      }}
                  }}

                if ((ctx->options & OPT_PARSE_STRICT) && j > 0 && ctx->errfile != NULL)
                  (void) fprintf (ctx->errfile, "WARNING: unknown key found\\n");

                if (ctx->options & OPT_PARSE_FULLKEY)
                  ret->_residual = resi;
              }}
        ''', indent=1)


def parse_json_to_c(obj, c_file, prefix):
    """
    Description: generate c language for parse json file
    Interface: None
    History: 2019-06-17
    """
    if not helpers.is_compound_type(obj.typ):
        return
    if obj.typ == 'object' or obj.typ == 'mapStringObject':
        if obj.subtypname:
            return
        obj_typename = typename = helpers.get_prefixed_name(obj.name, prefix)
    if obj.typ == 'array':
        obj_typename = typename = helpers.get_name_substr(obj.name, prefix)
        objs = obj.subtypobj
        if objs is None or obj.subtypname:
            return
    emit(c_file, f'''
        define_cleaner_function ({typename} *, free_{typename})
        {typename} *
        make_{typename} (yajl_val tree, const struct parser_context *ctx, parser_error *err)
        {{
            __auto_cleanup(free_{typename}) {typename} *ret = NULL;
            *err = NULL;
            (void) ctx;  /* Silence compiler warning.  */
            if (tree == NULL)
              return NULL;
            ret = calloc (1, sizeof (*ret));
            if (ret == NULL)
              return NULL;
    ''', indent=0)
    if obj.typ == 'mapStringObject':
        parse_map_string_obj(obj, c_file, prefix, obj_typename)

    if obj.typ == 'object' or (obj.typ == 'array' and obj.subtypobj):
        parse_obj_arr_obj(obj, c_file, prefix, obj_typename)
    c_file.append("    return move_ptr (ret);\n")
    c_file.append("}\n")
    c_file.append("\n")


def get_map_string_obj(obj, c_file, prefix):
    """
    Description: c language generate map string object
    Interface: None
    History: 2019-06-17
    """
    child = obj.children[0]
    if helpers.valid_basic_map_name(child.typ):
        childname = helpers.make_basic_map_name(child.typ)
    else:
        if child.subtypname:
            childname = child.subtypname
        else:
            childname = helpers.get_prefixed_name(child.name, prefix)

    emit(c_file, '''
        size_t len = 0, i;
        if (ptr != NULL)
            len = ptr->len;
    ''', indent=1)
    emit_beautify_off(c_file, '!len', indent=1)
    emit_gen_map_open(c_file, indent=1)
    check_gen_status(c_file, indent=1)

    emit(c_file, f'''
        if (len || (ptr != NULL && ptr->keys != NULL && ptr->{child.fixname} != NULL))
          {{
            for (i = 0; i < len; i++)
              {{
                char *str = ptr->keys[i] ? ptr->keys[i] : "";
                stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, strlen (str));
    ''', indent=1)

    check_gen_status(c_file, indent=3)

    emit(c_file, f'''
                stat = gen_{childname} (g, ptr->{child.fixname}[i], ctx, err);
    ''', indent=3)

    check_gen_status(c_file, indent=3)

    emit(c_file, '''
              }
          }
    ''', indent=2)
    emit_gen_map_close(c_file, indent=1)
    check_gen_status(c_file, indent=1)
    emit_beautify_on(c_file, '!len', indent=1)

def get_obj_arr_obj_array(obj, c_file, prefix):
    if obj.subtypobj or obj.subtyp == 'object':
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_name_substr(obj.name, prefix)

        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                size_t len = 0, i;
        ''', indent=1)
        emit_gen_key(c_file, obj.origname, indent=2)
        check_gen_status(c_file, indent=2)

        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                    len = ptr->{obj.fixname}_len;
        ''', indent=2)
        emit_beautify_off(c_file, '!len', indent=2)
        emit_gen_array_open(c_file, indent=2)
        check_gen_status(c_file, indent=2)

        emit(c_file, '''
                for (i = 0; i < len; i++)
                  {
        ''', indent=2)

        if obj.doublearray:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                    size_t j;
                    for (j = 0; j < ptr->{obj.fixname}_item_lens[i]; j++)
                      {{
                        stat = gen_{typename} (g, ptr->{obj.fixname}[i][j], ctx, err);
            ''', indent=3)
            check_gen_status(c_file, indent=4)
            emit(c_file, '''
                      }
            ''', indent=4)
            emit_gen_array_close(c_file, indent=3)
        else:
            emit(c_file, f'''
                    stat = gen_{typename} (g, ptr->{obj.fixname}[i], ctx, err);
            ''', indent=3)
            check_gen_status(c_file, indent=3)

        emit(c_file, '''
                  }
        ''', indent=2)
        emit_gen_array_close(c_file, indent=2)
        emit_beautify_on(c_file, '!len', indent=2)
        check_gen_status(c_file, indent=2)

        emit(c_file, '''
              }
        ''', indent=1)
    elif obj.subtyp == 'byte':
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL && ptr->{obj.fixname}_len))
              {{
                const char *str = "";
                size_t len = 0;
        ''', indent=1)
        emit_gen_key(c_file, obj.origname, indent=2)
        check_gen_status(c_file, indent=2)

        if obj.doublearray:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                {{
                    size_t i;
                    for (i = 0; i < ptr->{obj.fixname}_len; i++)
                      {{
                        if (ptr->{obj.fixname}[i] != NULL)
                            str = (const char *)ptr->{obj.fixname}[i];
                        else ()
                            str = "";
                        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, strlen(str));
                      }}
                }}
            ''', indent=2)
            emit_gen_array_close(c_file, indent=2)
        else:
            emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                  {{
                    str = (const char *)ptr->{obj.fixname};
                    len = ptr->{obj.fixname}_len;
                  }}
                stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, len);
            ''', indent=2)

        check_gen_status(c_file, indent=2)

        emit(c_file, '''
              }
        ''', indent=1)
    else:
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                size_t len = 0, i;
        ''', indent=1)
        emit_gen_key(c_file, obj.origname, indent=2)
        check_gen_status(c_file, indent=2)

        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                  len = ptr->{obj.fixname}_len;
        ''', indent=2)
        emit_beautify_off(c_file, '!len', indent=2)
        emit_gen_array_open(c_file, indent=2)
        check_gen_status(c_file, indent=2)

        emit(c_file, '''
                for (i = 0; i < len; i++)
                  {
        ''', indent=2)

        if obj.doublearray:
            typename = helpers.get_map_c_types(obj.subtyp)
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                    size_t j;
                    for (j = 0; j < ptr->{obj.fixname}_item_lens[i]; j++)
                      {{
            ''', indent=3)
            json_value_generator(c_file, 4, f"ptr->{obj.fixname}[i][j]", 'g', 'ctx', obj.subtyp)
            emit(c_file, '''
                      }
            ''', indent=4)
            emit_gen_array_close(c_file, indent=3)
        else:
            json_value_generator(c_file, 3, f"ptr->{obj.fixname}[i]", 'g', 'ctx', obj.subtyp)

        emit(c_file, '''
                  }
        ''', indent=2)
        emit_gen_array_close(c_file, indent=2)
        check_gen_status(c_file, indent=2)
        emit_beautify_on(c_file, '!len', indent=2)
        emit(c_file, '''
              }
        ''', indent=2)

def get_obj_arr_obj(obj, c_file, prefix):
    """
    Description: c language generate object or array object
    Interface: None
    History: 2019-06-17
    """
    if obj.typ == 'string':
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                char *str = "";
        ''', indent=1)
        emit_gen_key(c_file, obj.origname, indent=2)
        check_gen_status(c_file, indent=2)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                    str = ptr->{obj.fixname};
        ''', indent=2)
        json_value_generator(c_file, 2, "str", 'g', 'ctx', obj.typ)
        emit(c_file, '''
              }
        ''', indent=1)
    elif helpers.judge_data_type(obj.typ):
        if obj.typ == 'double':
            numtyp = 'double'
        elif obj.typ.startswith("uint") or obj.typ == 'GID' or obj.typ == 'UID':
            numtyp = 'long long unsigned int'
        else:
            numtyp = 'long long int'
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname}_present))
              {{
                {numtyp} num = 0;
        ''', indent=1)
        emit_gen_key(c_file, obj.origname, indent=2)
        check_gen_status(c_file, indent=2)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname})
                    num = ({numtyp})ptr->{obj.fixname};
        ''', indent=2)
        json_value_generator(c_file, 2, "num", 'g', 'ctx', obj.typ)
        emit(c_file, '''
              }
        ''', indent=1)
    elif helpers.judge_data_pointer_type(obj.typ):
        numtyp = helpers.obtain_data_pointer_type(obj.typ)
        if numtyp == "":
            return
        emit(c_file, f'''
            if ((ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                {helpers.get_map_c_types(numtyp)} num = 0;
        ''', indent=1)
        emit_gen_key(c_file, obj.origname, indent=2)
        check_gen_status(c_file, indent=2)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                  {{
                    num = ({helpers.get_map_c_types(numtyp)})*(ptr->{obj.fixname});
                  }}
        ''', indent=2)
        json_value_generator(c_file, 2, "num", 'g', 'ctx', numtyp)
        emit(c_file, '''
              }
        ''', indent=1)
    elif obj.typ == 'boolean':
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname}_present))
              {{
                bool b = false;
        ''', indent=1)
        emit_gen_key(c_file, obj.origname, indent=2)
        check_gen_status(c_file, indent=2)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname})
                    b = ptr->{obj.fixname};

        ''', indent=2)
        json_value_generator(c_file, 2, "b", 'g', 'ctx', obj.typ)
        emit(c_file, '''
              }
        ''', indent=1)
    elif obj.typ == 'object' or obj.typ == 'mapStringObject':
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_prefixed_name(obj.name, prefix)
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
        ''', indent=1)
        emit_gen_key(c_file, obj.origname, indent=2)
        check_gen_status(c_file, indent=2)
        emit(c_file, f'''
                stat = gen_{typename} (g, ptr != NULL ? ptr->{obj.fixname} : NULL, ctx, err);
        ''', indent=2)
        check_gen_status(c_file, indent=2)
        emit(c_file, '''
              }
        ''', indent=1)
    elif obj.typ == 'array':
        get_obj_arr_obj_array(obj, c_file, prefix)
    elif helpers.valid_basic_map_name(obj.typ):
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
        ''', indent=1)
        emit_gen_key(c_file, obj.fixname, indent=2)
        check_gen_status(c_file, indent=2)
        emit(c_file, f'''
                stat = gen_{helpers.make_basic_map_name(obj.typ)} (g, ptr ? ptr->{obj.fixname} : NULL, ctx, err);
        ''', indent=2)
        check_gen_status(c_file, indent=2)
        emit(c_file, '''
              }
        ''', indent=1)


def get_c_json(obj, c_file, prefix):
    """
    Description: c language generate json file
    Interface: None
    History: 2019-06-17
    """
    if not helpers.is_compound_type(obj.typ) or obj.subtypname:
        return
    if obj.typ == 'object' or obj.typ == 'mapStringObject':
        typename = helpers.get_prefixed_name(obj.name, prefix)
    elif obj.typ == 'array':
        typename = helpers.get_name_substr(obj.name, prefix)
        objs = obj.subtypobj
        if objs is None:
            return
    emit(c_file, f'''
        yajl_gen_status
        gen_{typename} (yajl_gen g, const {typename} *ptr, const struct parser_context *ctx, parser_error *err)
        {{
            yajl_gen_status stat = yajl_gen_status_ok;
            *err = NULL;
            (void) ptr;  /* Silence compiler warning.  */
    ''', indent=0)
    if obj.typ == 'mapStringObject':
        get_map_string_obj(obj, c_file, prefix)
    elif obj.typ == 'object' or (obj.typ == 'array' and obj.subtypobj):
        nodes = obj.children if obj.typ == 'object' else obj.subtypobj
        if nodes is None:
            emit_beautify_off(c_file, 'true', indent=1)

        emit_gen_map_open(c_file, indent=1)
        check_gen_status(c_file, indent=1)
        for i in nodes or []:
            get_obj_arr_obj(i, c_file, prefix)
        if obj.typ == 'object':
            if obj.children is not None:
                emit(c_file, '''
                    if (ptr != NULL && ptr->_residual != NULL)
                      {
                        stat = gen_yajl_object_residual (ptr->_residual, g, err);
                        if (yajl_gen_status_ok != stat)
                            GEN_SET_ERROR_AND_RETURN (stat, err);
                      }
                ''', indent=1)
        emit_gen_map_close(c_file, indent=1)
        check_gen_status(c_file, indent=1)
        if nodes is None:
            emit_beautify_on(c_file, 'true', indent=1)
    c_file.append("    return yajl_gen_status_ok;\n")
    c_file.append("}\n")
    c_file.append("\n")


def read_val_generator(c_file, level, src, dest, typ, keyname, obj_typename):
    """
    Description: read value generateor
    Interface: None
    History: 2019-06-17
    """
    if helpers.valid_basic_map_name(typ):
        emit(c_file, f'''
            yajl_val val = {src};
            if (val != NULL)
              {{
                {dest} = make_{helpers.make_basic_map_name(typ)} (val, ctx, err);
                if ({dest} == NULL)
                  {{
        ''', indent=level)
        emit_value_error(c_file, keyname, indent=level + 2)
        emit(c_file, '''
                  }
              }
        ''', indent=level)
    elif typ == 'string':
        emit(c_file, f'''
            yajl_val val = {src};
            if (val != NULL)
              {{
                char *str = YAJL_GET_STRING (val);
                {dest} = strdup (str ? str : "");
                if ({dest} == NULL)
                  return NULL;
              }}
        ''', indent=level)
    elif helpers.judge_data_type(typ):
        conv_func, dest_cast = get_numeric_conversion_info(typ)
        emit(c_file, f'''
            yajl_val val = {src};
            if (val != NULL)
              {{
                int invalid;
        ''', indent=level)
        emit_invalid_type_check(c_file, 'YAJL_IS_NUMBER', indent=level + 1)
        emit(c_file, f'''
                    invalid = {conv_func} (YAJL_GET_NUMBER (val), {dest_cast}{dest});
                if (invalid)
                  {{
                    if (asprintf (err, "Invalid value '%s' with type '{typ}' for key '{keyname}': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                        *err = strdup ("error allocating memory");
                    return NULL;
                  }}
        ''', indent=level + 1)
        if '[' not in dest:
            emit(c_file, f'''
                    {dest}_present = 1;
            ''', indent=level + 1)
        emit(c_file, f'''
              }}
        ''', indent=level)
    elif helpers.judge_data_pointer_type(typ):
        num_type = helpers.obtain_data_pointer_type(typ)
        if num_type == "":
            return
        emit(c_file, f'''
            yajl_val val = {src};
            if (val != NULL)
              {{
                {dest} = calloc (1, sizeof ({helpers.get_map_c_types(num_type)}));
                if ({dest} == NULL)
                    return NULL;
                int invalid;
        ''', indent=level)
        emit_invalid_type_check(c_file, 'YAJL_IS_NUMBER', indent=level + 1)
        emit(c_file, f'''
                invalid = common_safe_{num_type} (YAJL_GET_NUMBER (val), {dest});
                if (invalid)
                  {{
                    if (asprintf (err, "Invalid value '%s' with type '{typ}' for key '{keyname}': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                        *err = strdup ("error allocating memory");
                    return NULL;
                  }}
              }}
        ''', indent=level)
    elif typ == 'boolean':
        emit(c_file, f'''
            yajl_val val = {src};
            if (val != NULL)
              {{
                {dest} = YAJL_IS_TRUE(val);
        ''', indent=level)
        if '[' not in dest:
            emit(c_file, f'''
                    {dest}_present = 1;
              }}
            else
              {{
                val = {src.replace('yajl_t_true', 'yajl_t_false')};
                if (val != NULL)
                  {{
                    {dest} = 0;
                    {dest}_present = 1;
                  }}
              }}
            ''', indent=level + 1)
        else:
            emit(c_file, f'''
              }}
            ''', indent=level)
    elif typ == 'booleanPointer':
        emit(c_file, f'''
            yajl_val val = {src};
            if (val != NULL)
              {{
                {dest} = calloc (1, sizeof (bool));
                if ({dest} == NULL)
                    return NULL;
                *({dest}) = YAJL_IS_TRUE(val);
              }}
            else
             {{
               val = get_val (tree, "{keyname}", yajl_t_false);
               if (val != NULL)
                 {{
                   {dest} = calloc (1, sizeof (bool));
                   if ({dest} == NULL)
                     return NULL;
                   *({dest}) = YAJL_IS_TRUE(val);
                 }}
             }}
        ''', indent=level)


def make_clone(obj, c_file, prefix):
    """
    Description: generate a clone operation for the specified object
    Interface: None
    History: 2024-09-03
    """

    if not helpers.is_compound_type(obj.typ) or obj.subtypname:
        return
    typename = helpers.get_prefixed_name(obj.name, prefix)
    case = obj.typ
    result = {'mapStringObject': lambda x: [],
              'object': lambda x: x.children,
              'array': lambda x: x.subtypobj}[case](obj)
    objs = result
    if obj.typ == 'array':
        if objs is None:
            return
        typename = helpers.get_name_substr(obj.name, prefix)

    emit(c_file, f'''
        {typename} *
        clone_{typename} ({typename} *src)
        {{
            (void) src;  /* Silence compiler warning.  */
            __auto_cleanup(free_{typename}) {typename} *ret = NULL;

            ret = calloc (1, sizeof (*ret));
            if (ret == NULL)
              return NULL;
    ''', indent=0)

    nodes = obj.children if obj.subtypobj is None else obj.subtypobj
    for i in nodes or []:
        if helpers.judge_data_type(i.typ) or i.typ == 'boolean':
            emit(c_file, f'''
                ret->{i.fixname} = src->{i.fixname};
                ret->{i.fixname}_present = src->{i.fixname}_present;
            ''', indent=1)
        elif i.typ == 'object':
            node_name = i.subtypname or helpers.get_prefixed_name(i.name, prefix)
            if obj.typ != 'mapStringObject':
                emit(c_file, f'''
                    if (src->{i.fixname})
                      {{
                        ret->{i.fixname} = clone_{node_name} (src->{i.fixname});
                        if (ret->{i.fixname} == NULL)
                          return NULL;
                      }}
                ''', indent=1)
            else:
                emit(c_file, f'''
                    if (src->{i.fixname})
                      {{
                        size_t i;
                        ret->{i.fixname} = calloc (src->len + 1, sizeof (*ret->{i.fixname}));
                        for (i = 0; i < src->len; i++)
                          {{
                             ret->{i.fixname}[i] = clone_{node_name} (src->{i.fixname}[i]);
                             if (ret->{i.fixname}[i] == NULL)
                               return NULL;
                          }}
                      }}
                ''', indent=1)
        elif i.typ == 'string':
            emit(c_file, f'''
                if (src->{i.fixname})
                  {{
                    ret->{i.fixname} = strdup (src->{i.fixname});
                    if (ret->{i.fixname} == NULL)
                      return NULL;
                  }}
            ''', indent=1)
        elif i.typ == 'array':
            emit(c_file, f'''
                if (src->{i.fixname})
                  {{
                    ret->{i.fixname}_len = src->{i.fixname}_len;
                    ret->{i.fixname} = calloc (src->{i.fixname}_len + 1, sizeof (*ret->{i.fixname}));
                    if (ret->{i.fixname} == NULL)
                      return NULL;
                    for (size_t i = 0; i < src->{i.fixname}_len; i++)
                      {{
            ''', indent=1)
            if helpers.judge_data_type(i.subtyp) or i.subtyp == 'boolean':
               emit(c_file, f'''
                           ret->{i.fixname}[i] = src->{i.fixname}[i];
               ''', indent=3)
            elif i.subtyp == 'object':
                typename = helpers.get_prefixed_name(i.name, prefix)
                if i.subtypname is not None:
                    typename = i.subtypname
                maybe_element = "_element" if i.subtypname is None else ""
                if i.doublearray:
                    emit(c_file, f'''
                                ret->{i.fixname}_item_lens[i] = src->{i.fixname}_item_lens[i];
                                ret->{i.fixname}[i] = calloc (ret->{i.fixname}_item_lens[i] + 1, sizeof (**ret->{i.fixname}[i]));
                                if (ret->{i.fixname}[i] == NULL)
                                    return NULL;
                                for (size_t j = 0; j < src->{i.fixname}_item_lens[i]; j++)
                                  {{
                                    ret->{i.fixname}[i][j] = clone_{typename}{maybe_element} (src->{i.fixname}[i][j]);
                                    if (ret->{i.fixname}[i][j] == NULL)
                                        return NULL;
                                  }}
                    ''', indent=3)
                else:
                    emit(c_file, f'''
                                ret->{i.fixname}[i] = clone_{typename}{maybe_element} (src->{i.fixname}[i]);
                                if (ret->{i.fixname}[i] == NULL)
                                    return NULL;
                    ''', indent=3)

            elif i.subtyp == 'string':
                if i.doublearray:
                    emit(c_file, f'''
                                ret->{i.fixname}[i] = calloc (ret->{i.fixname}_item_lens[i] + 1, sizeof (**ret->{i.fixname}[i]));
                                if (ret->{i.fixname}[i] == NULL)
                                    return NULL;
                                for (size_t j = 0; j < src->{i.fixname}_item_lens[i]; j++)
                                  {{
                                    ret->{i.fixname}[i][j] = strdup (src->{i.fixname}[i][j]);
                                    if (ret->{i.fixname}[i][j] == NULL)
                                        return NULL;
                                  }}
                    ''', indent=3)
                else:
                    emit(c_file, f'''
                                if (src->{i.fixname}[i])
                                  {{
                                    ret->{i.fixname}[i] = strdup (src->{i.fixname}[i]);
                                    if (ret->{i.fixname}[i] == NULL)
                                      return NULL;
                                  }}
                    ''', indent=3)
            else:
                raise Exception("Unimplemented type for array clone: %s (%s)" % (i.subtyp, i.subtypname))
            emit(c_file, f'''
                          }}
                      }}
            ''', indent=2)
        elif i.typ == 'mapStringString':
            emit(c_file, f'''
                ret->{i.fixname} = clone_map_string_string (src->{i.fixname});
                if (ret->{i.fixname} == NULL)
                    return NULL;
            ''', indent=1)
        elif i.typ == 'mapStringObject':
            if i.subtypname is not None:
                subtypname = i.subtypname
                maybe_element = "_element"
            else:
                subtypname = i.children[0].subtypname
                maybe_element = ""

            emit(c_file, f'''
                if (src->{i.fixname})
                  {{
                    ret->{i.fixname} = calloc (1, sizeof (*ret->{i.fixname}));
                    if (ret->{i.fixname} == NULL)
                        return NULL;
                    ret->{i.fixname}->len = src->{i.fixname}->len;
                    ret->{i.fixname}->keys = calloc (src->{i.fixname}->len + 1, sizeof (char *));
                    if (ret->{i.fixname}->keys == NULL)
                        return NULL;
                    ret->{i.fixname}->values = calloc (src->{i.fixname}->len + 1, sizeof (*ret->{i.fixname}->values));
                    if (ret->{i.fixname}->values == NULL)
                        return NULL;
                    for (size_t i = 0; i < ret->{i.fixname}->len; i++)
                      {{
                        ret->{i.fixname}->keys[i] = strdup (src->{i.fixname}->keys[i]);
                        if (ret->{i.fixname}->keys[i] == NULL)
                          return NULL;
                        ret->{i.fixname}->values[i] = clone_{subtypname}{maybe_element} (src->{i.fixname}->values[i]);
                        if (ret->{i.fixname}->values[i] == NULL)
                          return NULL;
                      }}
                  }}
            ''', indent=1)
        else:
            raise Exception("Unimplemented type for clone: %s" % i.typ)

    c_file.append("    return move_ptr (ret);\n")
    c_file.append("}\n")
    c_file.append("\n")


def json_value_generator(c_file, level, src, dst, ptx, typ):
    """
    Description: json value generateor
    Interface: None
    History: 2019-06-17
    """
    if helpers.valid_basic_map_name(typ):
        emit(c_file, f'''
            stat = gen_{helpers.make_basic_map_name(typ)} ({dst}, {src}, {ptx}, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)
    elif typ == 'string':
        emit(c_file, f'''
            stat = yajl_gen_string ((yajl_gen){dst}, (const unsigned char *)({src}), strlen ({src}));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)
    elif helpers.judge_data_type(typ):
        if typ == 'double':
            emit(c_file, f'''
                stat = yajl_gen_double ((yajl_gen){dst}, {src});
            ''', indent=level)
        elif typ.startswith("uint") or typ == 'GID' or typ == 'UID':
            emit(c_file, f'''
                stat = map_uint ({dst}, {src});
            ''', indent=level)
        else:
            emit(c_file, f'''
                stat = map_int ({dst}, {src});
            ''', indent=level)
        emit(c_file, f'''
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)
    elif typ == 'boolean':
        emit(c_file, f'''
            stat = yajl_gen_bool ((yajl_gen){dst}, (int)({src}));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)

def make_c_array_free (i, c_file, prefix):
    if helpers.valid_basic_map_name(i.subtyp):
        free_func = helpers.make_basic_map_name(i.subtyp)
        emit(c_file, f'''
            if (ptr->{i.fixname} != NULL)
              {{
                size_t i;
                for (i = 0; i < ptr->{i.fixname}_len; i++)
                  {{
                    if (ptr->{i.fixname}[i] != NULL)
                      {{
                        free_{free_func} (ptr->{i.fixname}[i]);
                        ptr->{i.fixname}[i] = NULL;
                      }}
                  }}
        ''', indent=1)
        free_and_null(c_file, "ptr", i.fixname, indent=2)
        emit(c_file, '''
              }
        ''', indent=1)
    elif i.subtyp == 'string':
        c_file_str(c_file, i)
    elif not helpers.is_compound_type(i.subtyp):
        emit(c_file, '''
           {
        ''', indent=0)
        if i.doublearray:
            emit(c_file, f'''
                    size_t i;
                    for (i = 0; i < ptr->{i.fixname}_len; i++)
                      {{
            ''', indent=3)
            free_and_null(c_file, "ptr", f"{i.fixname}[i]", indent=4)
            emit(c_file, '''
                      }
            ''', indent=3)
            free_and_null(c_file, "ptr", f"{i.fixname}_item_lens", indent=3)
        free_and_null(c_file, "ptr", i.fixname, indent=2)
        emit(c_file, '''
            }
        ''', indent=1)
    elif i.subtyp == 'object' or i.subtypobj is not None:
        if i.subtypname is not None:
            free_func = i.subtypname
        else:
            free_func = helpers.get_name_substr(i.name, prefix)

        emit(c_file, f'''
            if (ptr->{i.fixname} != NULL)
              {{
                size_t i;
                for (i = 0; i < ptr->{i.fixname}_len; i++)
                  {{
        ''', indent=1)

        if i.doublearray:
            emit(c_file, f'''
                  size_t j;
                  for (j = 0; j < ptr->{i.fixname}_item_lens[i]; j++)
                    {{
                      free_{free_func} (ptr->{i.fixname}[i][j]);
                      ptr->{i.fixname}[i][j] = NULL;
                  }}
            ''', indent=2)
            free_and_null(c_file, "ptr", f"{i.fixname}[i]", indent=2)
        else:
            emit(c_file, f'''
                  if (ptr->{i.fixname}[i] != NULL)
                    {{
                      free_{free_func} (ptr->{i.fixname}[i]);
                      ptr->{i.fixname}[i] = NULL;
                    }}
            ''', indent=2)

        emit(c_file, '''
                  }
        ''', indent=2)

        if i.doublearray:
            free_and_null(c_file, "ptr", f"{i.fixname}_item_lens", indent=2)

        free_and_null(c_file, "ptr", i.fixname, indent=2)

        emit(c_file, '''
              }
        ''', indent=1)

    c_typ = helpers.obtain_pointer(i.name, i.subtypobj, prefix)
    if c_typ == "":
        return True
    if i.subtypname is not None:
        c_typ = c_typ + "_element"

    emit(c_file, f'''
        free_{c_typ} (ptr->{i.fixname});
        ptr->{i.fixname} = NULL;
    ''', indent=1)

    return False

def make_c_free (obj, c_file, prefix):
    """
    Description: generate c free function
    Interface: None
    History: 2019-06-17
    """
    if not helpers.is_compound_type(obj.typ) or obj.subtypname:
        return
    typename = helpers.get_prefixed_name(obj.name, prefix)
    case = obj.typ
    result = {'mapStringObject': lambda x: [],
              'object': lambda x: x.children,
              'array': lambda x: x.subtypobj}[case](obj)
    objs = result
    if obj.typ == 'array':
        if objs is None:
            return
        typename = helpers.get_name_substr(obj.name, prefix)

    emit(c_file, f'''
        void
        free_{typename} ({typename} *ptr)
        {{
            if (ptr == NULL)
                return;
    ''', indent=0)
    if obj.typ == 'mapStringObject':
        child = obj.children[0]
        if helpers.valid_basic_map_name(child.typ):
            childname = helpers.make_basic_map_name(child.typ)
        else:
            if child.subtypname:
                childname = child.subtypname
            else:
                childname = helpers.get_prefixed_name(child.name, prefix)
        c_file_map_str(c_file, child, childname)
    for i in objs or []:
        if helpers.valid_basic_map_name(i.typ):
            free_func = helpers.make_basic_map_name(i.typ)
            emit(c_file, f'''
                free_{free_func} (ptr->{i.fixname});
                ptr->{i.fixname} = NULL;
            ''', indent=1)
        if i.typ == 'mapStringObject':
            if i.subtypname:
                free_func = i.subtypname
            else:
                free_func = helpers.get_prefixed_name(i.name, prefix)
            emit(c_file, f'''
                free_{free_func} (ptr->{i.fixname});
                ptr->{i.fixname} = NULL;
            ''', indent=1)
        elif i.typ == 'array':
            if make_c_array_free (i, c_file, prefix):
                continue
        else:
            typename = helpers.get_prefixed_name(i.name, prefix)
            if i.typ == 'string' or i.typ == 'booleanPointer' or \
                    helpers.judge_data_pointer_type(i.typ):
                emit(c_file, f'''
                    free (ptr->{i.fixname});
                    ptr->{i.fixname} = NULL;
                ''', indent=1)
            elif i.typ == 'object':
                if i.subtypname is not None:
                    typename = i.subtypname
                emit(c_file, f'''
                    if (ptr->{i.fixname} != NULL)
                      {{
                        free_{typename} (ptr->{i.fixname});
                        ptr->{i.fixname} = NULL;
                      }}
                ''', indent=1)

    if obj.typ == 'object':
        if obj.children is not None:
            emit(c_file, '''
                yajl_tree_free (ptr->_residual);
                ptr->_residual = NULL;
            ''', indent=1)

    emit(c_file, '''
            free (ptr);
        }

    ''', indent=1)


def c_file_map_str(c_file, child, childname):
    """
    Description: generate c code for map string
    Interface: None
    History: 2019-10-31
    """
    emit(c_file, f'''
        if (ptr->keys != NULL && ptr->{child.fixname} != NULL)
          {{
            size_t i;
            for (i = 0; i < ptr->len; i++)
              {{
    ''', indent=1)

    free_and_null(c_file, "ptr", "keys[i]", indent=3)

    emit(c_file, f'''
                free_{childname} (ptr->{child.fixname}[i]);
                ptr->{child.fixname}[i] = NULL;
              }}
    ''', indent=3)

    free_and_null(c_file, "ptr", "keys", indent=2)
    free_and_null(c_file, "ptr", child.fixname, indent=2)

    emit(c_file, '''
          }
    ''', indent=1)

def c_file_str(c_file, i):
    """
    Description: generate c code template
    Interface: None
    History: 2019-10-31
    """
    emit(c_file, f'''
        if (ptr->{i.fixname} != NULL)
          {{
            size_t i;
            for (i = 0; i < ptr->{i.fixname}_len; i++)
              {{
    ''', indent=1)

    if i.doublearray:
        emit(c_file, f'''
                size_t j;
                for (j = 0; j < ptr->{i.fixname}_item_lens[i]; j++)
                  {{
        ''', indent=3)
        free_and_null(c_file, "ptr", f"{i.fixname}[i][j]", indent=4)
        emit(c_file, '''
                  }
        ''', indent=3)

    emit(c_file, f'''
                if (ptr->{i.fixname}[i] != NULL)
                  {{
    ''', indent=3)

    free_and_null(c_file, "ptr", f"{i.fixname}[i]", indent=4)

    emit(c_file, '''
                  }
              }
    ''', indent=3)

    if i.doublearray:
        free_and_null(c_file, "ptr", f"{i.fixname}_item_lens", indent=2)

    free_and_null(c_file, "ptr", i.fixname, indent=2)

    emit(c_file, '''
          }
    ''', indent=1)


def src_reflect(structs, schema_info, c_file, root_typ):
    """
    Description: reflect code
    Interface: None
    History: 2019-06-17
    """
    emit(c_file, f'''
        /* Generated from {schema_info.name.basename}. Do not edit!  */

        #ifndef _GNU_SOURCE
        #define _GNU_SOURCE
        #endif
        #include <string.h>
        #include <ocispec/read-file.h>
        #include "ocispec/{schema_info.header.basename}"

        #define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)
        #define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
    ''', indent=0)
    for i in structs:
        append_c_code(i, c_file, schema_info.prefix)

    length = len(structs)
    get_c_epilog(c_file, schema_info.prefix, root_typ, structs[length - 1])

def get_c_epilog_for_array_make_parse(c_file, prefix, typ, obj):
    c_typ = helpers.get_prefixed_pointer(obj.name, obj.subtyp, prefix) or \
        helpers.get_map_c_types(obj.subtyp)
    if obj.subtypobj is not None:
        c_typ = helpers.get_name_substr(obj.name, prefix)
    if c_typ == "":
        return
    typename = helpers.get_top_array_type_name(obj.name, prefix)

    emit(c_file, f'''

        define_cleaner_function ({typename} *, free_{typename})
        {typename}
        *make_{typename} (yajl_val tree, const struct parser_context *ctx, parser_error *err)
        {{
            __auto_cleanup(free_{typename}) {typename} *ptr = NULL;
            size_t i, alen;

            (void) ctx;

            if (tree == NULL || err == NULL || YAJL_GET_ARRAY (tree) == NULL)
              return NULL;
            *err = NULL;
            alen = YAJL_GET_ARRAY_NO_CHECK (tree)->len;
            if (alen == 0)
              return NULL;
            ptr = calloc (1, sizeof ({typename}));
            if (ptr == NULL)
              return NULL;
            ptr->items = calloc (alen + 1, sizeof(*ptr->items));
            if (ptr->items == NULL)
              return NULL;
            ptr->len = alen;
    ''', indent=0)

    if obj.doublearray:
        emit(c_file, '''
            ptr->subitem_lens = calloc ( alen + 1, sizeof (size_t));
            if (ptr->subitem_lens == NULL)
              return NULL;
        ''', indent=1)

    emit(c_file, '''

            for (i = 0; i < alen; i++)
              {
                yajl_val work = YAJL_GET_ARRAY_NO_CHECK (tree)->values[i];
    ''', indent=1)

    if obj.subtypobj or obj.subtyp == 'object':
        if obj.subtypname:
            subtypename = obj.subtypname
        else:
            subtypename = helpers.get_name_substr(obj.name, prefix)

        if obj.doublearray:
            emit(c_file, f'''
                        size_t j;
                        ptr->items[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(work)->len + 1, sizeof (**ptr->items));
                        if (ptr->items[i] == NULL)
                          return NULL;
                        yajl_val *tmps = YAJL_GET_ARRAY_NO_CHECK(work)->values;
                        for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(work)->len; j++)
                          {{
                              ptr->items[i][j] = make_{subtypename} (tmps[j], ctx, err);
                              if (ptr->items[i][j] == NULL)
                                return NULL;
                              ptr->subitem_lens[i] += 1;
                          }}
            ''', indent=2)
        else:
            emit(c_file, f'''
                        ptr->items[i] = make_{subtypename} (work, ctx, err);
                        if (ptr->items[i] == NULL)
                          return NULL;
            ''', indent=2)
    elif obj.subtyp == 'byte':
        if obj.doublearray:
            emit(c_file, '''
                        char *str = YAJL_GET_STRING (work);
                        ptr->items[j] = (uint8_t *)strdup (str ? str : "");
                        if (ptr->items[j] == NULL)
                          return NULL;
            ''', indent=2)
        else:
            emit(c_file, '''
                        char *str = YAJL_GET_STRING (tree);
                        memcpy(ptr->items, str ? str : "", strlen(str ? str : ""));
                        break;
            ''', indent=2)
    else:
        if obj.doublearray:
            emit(c_file, '''
                        ptr->items[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(work)->len + 1, sizeof (**ptr->items));
                        if (ptr->items[i] == NULL)
                          return NULL;
                        size_t j;
                        yajl_val *tmps = YAJL_GET_ARRAY_NO_CHECK(work)->values;
                        for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(work)->len; j++)
                          {
            ''', indent=2)
            read_val_generator(c_file, 3, 'tmps[j]', \
                                "ptr->items[i][j]", obj.subtyp, obj.origname, c_typ)
            emit(c_file, '''
                            ptr->subitem_lens[i] += 1;
                          }
            ''', indent=3)
        else:
            read_val_generator(c_file, 2, 'work', \
                                "ptr->items[i]", obj.subtyp, obj.origname, c_typ)

    emit(c_file, '''

      }
    ''', indent=1)
    c_file.append("    return move_ptr(ptr);\n")
    c_file.append("}\n")
    c_file.append("\n")

def get_c_epilog_for_array_make_free(c_file, prefix, typ, obj):
    c_typ = helpers.get_prefixed_pointer(obj.name, obj.subtyp, prefix) or \
        helpers.get_map_c_types(obj.subtyp)
    if obj.subtypobj is not None:
        c_typ = helpers.get_name_substr(obj.name, prefix)
    if c_typ == "":
        return
    typename = helpers.get_top_array_type_name(obj.name, prefix)

    emit(c_file, f'''


        void free_{typename} ({typename} *ptr)
        {{
            size_t i;

            if (ptr == NULL)
                return;

            for (i = 0; i < ptr->len; i++)
              {{
    ''', indent=0)

    if helpers.valid_basic_map_name(obj.subtyp):
        free_func = helpers.make_basic_map_name(obj.subtyp)
        emit(c_file, f'''
                        if (ptr->items[i] != NULL)
                          {{
                            free_{free_func} (ptr->items[i]);
                            ptr->items[i] = NULL;
                          }}
        ''', indent=2)
    elif obj.subtyp == 'string':
        if obj.doublearray:
            emit(c_file, '''
                        size_t j;
                        for (j = 0; j < ptr->subitem_lens[i]; j++)
                          {
                            free (ptr->items[i][j]);
                            ptr->items[i][j] = NULL;
                          }
                        free (ptr->items[i]);
                        ptr->items[i] = NULL;
            ''', indent=2)
        else:
            emit(c_file, '''
                        free (ptr->items[i]);
                        ptr->items[i] = NULL;
            ''', indent=2)
    elif not helpers.is_compound_type(obj.subtyp):
        if obj.doublearray:
            emit(c_file, '''
                        free (ptr->items[i]);
                        ptr->items[i] = NULL;
            ''', indent=2)
    elif obj.subtyp == 'object' or obj.subtypobj is not None:
        if obj.subtypname is not None:
            free_func = obj.subtypname
        else:
            free_func = helpers.get_name_substr(obj.name, prefix)

        if obj.doublearray:
            emit(c_file, f'''
                          size_t j;
                          for (j = 0; j < ptr->subitem_lens[i]; j++)
                            {{
                              free_{free_func} (ptr->items[i][j]);
                              ptr->items[i][j] = NULL;
                            }}
                            free (ptr->items[i]);
                            ptr->items[i] = NULL;
            ''', indent=2)
        else:
            emit(c_file, f'''
                          free_{free_func} (ptr->items[i]);
                          ptr->items[i] = NULL;
            ''', indent=2)

    emit(c_file, '''
              }
    ''', indent=1)
    if obj.doublearray:
        emit(c_file, '''
            free (ptr->subitem_lens);
            ptr->subitem_lens = NULL;
        ''', indent=1)

    c_typ = helpers.obtain_pointer(obj.name, obj.subtypobj, prefix)
    if c_typ != "":
        if obj.subobj is not None:
            c_typ = c_typ + "_element"
        emit(c_file, f'''
            free_{c_typ} (ptr->items);
            ptr->items = NULL;
        ''', indent=1)
        return

    emit(c_file, '''
            free (ptr->items);
            ptr->items = NULL;

            free (ptr);
        }
    ''', indent=1)

def get_c_epilog_for_array_make_gen(c_file, prefix, typ, obj):
    c_typ = helpers.get_prefixed_pointer(obj.name, obj.subtyp, prefix) or \
        helpers.get_map_c_types(obj.subtyp)
    if obj.subtypobj is not None:
        c_typ = helpers.get_name_substr(obj.name, prefix)
    if c_typ == "":
        return
    typename = helpers.get_top_array_type_name(obj.name, prefix)

    emit(c_file, f'''
        yajl_gen_status gen_{typename} (yajl_gen g, const {typename} *ptr, const struct parser_context *ctx,
                               parser_error *err)
        {{
            yajl_gen_status stat;
            size_t i;

            if (ptr == NULL)
                return yajl_gen_status_ok;
            *err = NULL;
    ''', indent=0)

    if obj.subtypobj or obj.subtyp == 'object':
        c_file.append('\n')
        emit_gen_array_open(c_file, indent=1)
        check_gen_status(c_file, indent=1)
        emit(c_file, '''
            for (i = 0; i < ptr->len; i++)
              {
        ''', indent=1)

        if obj.subtypname:
            subtypename = obj.subtypname
        else:
            subtypename = helpers.get_name_substr(obj.name, prefix)
        emit(c_file, '''
              {
        ''', indent=1)
        if obj.doublearray:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                        size_t j;
                        for (j = 0; j < ptr->subitem_lens[i]; j++)
                          {{
                            stat = gen_{subtypename} (g, ptr->items[i][j], ctx, err);
                            if (stat != yajl_gen_status_ok)
                                GEN_SET_ERROR_AND_RETURN (stat, err);
                          }}
            ''', indent=3)
            emit_gen_array_close(c_file, indent=3)
        else:
            emit(c_file, f'''
                        stat = gen_{subtypename} (g, ptr->items[i], ctx, err);
            ''', indent=3)
            check_gen_status(c_file, indent=3)
        emit(c_file, '''

                    }
              }
        ''', indent=2)
        emit_gen_array_close(c_file, indent=1)
    elif obj.subtyp == 'byte':
        emit(c_file, '''
            {
                    const char *str = NULL;
        ''', indent=1)
        if obj.doublearray:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, '''
                        {
                            size_t i;
                            for (i = 0; i < ptr->len; i++)
                              {
                                if (ptr->items[i] != NULL)
                                    str = (const char *)ptr->items[i];
                                else ()
                                    str = "";
                                stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, strlen(str));
                              }
                        }
            ''', indent=3)
            emit_gen_array_close(c_file, indent=3)
        else:
            emit(c_file, '''
                    if (ptr != NULL && ptr->items != NULL)
                      {
                        str = (const char *)ptr->items;
                      }
                    stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, ptr->len);
            ''', indent=2)
        emit(c_file, '''
            }
        ''', indent=1)
    else:
        c_file.append('\n')
        emit_gen_array_open(c_file, indent=1)
        check_gen_status(c_file, indent=1)
        emit(c_file, '''
            for (i = 0; i < ptr->len; i++)
              {
        ''', indent=1)
        emit(c_file, '''
                {
        ''', indent=2)
        if obj.doublearray:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, '''
                        size_t j;
                        for (j = 0; j < ptr->subitem_lens[i]; j++)
                          {
            ''', indent=3)
            json_value_generator(c_file, 4, "ptr->items[i][j]", 'g', 'ctx', obj.subtyp)
            emit(c_file, '''
                        }
            ''', indent=3)
            emit_gen_array_close(c_file, indent=3)
        else:
            json_value_generator(c_file, 3, "ptr->items[i]", 'g', 'ctx', obj.subtyp)

        emit(c_file, '''

                    }
              }
        ''', indent=2)
        emit_gen_array_close(c_file, indent=1)


    emit(c_file, '''

    if (ptr->len > 0 && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 1);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    ''', indent=1)
    c_file.append("    return yajl_gen_status_ok;\n")
    c_file.append("}\n")
    c_file.append("\n")

def get_c_epilog_for_array(c_file, prefix, typ, obj):
    typename = helpers.get_top_array_type_name(obj.name, prefix)

    get_c_epilog_for_array_make_parse(c_file, prefix, typ, obj)
    get_c_epilog_for_array_make_free(c_file, prefix, typ, obj)
    get_c_epilog_for_array_make_gen(c_file, prefix, typ, obj)


def get_c_epilog(c_file, prefix, typ, obj):
    """
    Description: generate c language epilogue
    Interface: None
    History: 2019-06-17
    """
    typename = prefix
    if typ != 'array' and typ != 'object':
        return
    if typ == 'array':
        typename = helpers.get_top_array_type_name(obj.name, prefix)
        get_c_epilog_for_array(c_file, prefix, typ, obj)

    emit(c_file, f'''

        {typename} *
        {typename}_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)
        {{
            {typename} *ptr = NULL;
            size_t filesize;
            __auto_free char *content = NULL;

            if (filename == NULL || err == NULL)
              return NULL;

            *err = NULL;
            content = read_file (filename, &filesize);
            if (content == NULL)
              {{
                if (asprintf (err, "cannot read the file: %s", filename) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
              }}
            ptr = {typename}_parse_data (content, ctx, err);
            return ptr;
        }}
    ''', indent=0)

    emit(c_file, f'''
        {typename} *
        {typename}_parse_file_stream (FILE *stream, const struct parser_context *ctx, parser_error *err)
        {{
            {typename} *ptr = NULL;
            size_t filesize;
            __auto_free char *content = NULL;

            if (stream == NULL || err == NULL)
              return NULL;

            *err = NULL;
            content = fread_file (stream, &filesize);
            if (content == NULL)
              {{
                *err = strdup ("cannot read the file");
                return NULL;
              }}
            ptr = {typename}_parse_data (content, ctx, err);
            return ptr;
        }}
    ''', indent=0)

    emit(c_file, f'''

        define_cleaner_function (yajl_val, yajl_tree_free)

        {typename} *
        {typename}_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)
        {{
            {typename} *ptr = NULL;
            __auto_cleanup(yajl_tree_free) yajl_val tree = NULL;
            char errbuf[1024];
            struct parser_context tmp_ctx = {{ 0 }};

            if (jsondata == NULL || err == NULL)
              return NULL;

            *err = NULL;
            if (ctx == NULL)
             ctx = (const struct parser_context *)(&tmp_ctx);

            tree = yajl_tree_parse (jsondata, errbuf, sizeof (errbuf));
            if (tree == NULL)
              {{
                if (asprintf (err, "cannot parse the data: %s", errbuf) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
              }}
            ptr = make_{typename} (tree, ctx, err);
            return ptr;
        }}
    ''', indent=0)

    emit(c_file, '''

        static void
        cleanup_yajl_gen (yajl_gen g)
        {
            if (!g)
              return;
            yajl_gen_clear (g);
            yajl_gen_free (g);
        }

        define_cleaner_function (yajl_gen, cleanup_yajl_gen)

    ''', indent=0)

    emit(c_file, f'''

        char *
        {typename}_generate_json (const {typename} *ptr, const struct parser_context *ctx, parser_error *err)
        {{
            __auto_cleanup(cleanup_yajl_gen) yajl_gen g = NULL;
            struct parser_context tmp_ctx = {{ 0 }};
            const unsigned char *gen_buf = NULL;
            char *json_buf = NULL;
            size_t gen_len = 0;

            if (ptr == NULL || err == NULL)
              return NULL;

            *err = NULL;
            if (ctx == NULL)
                ctx = (const struct parser_context *)(&tmp_ctx);

            if (!json_gen_init(&g, ctx))
              {{
                *err = strdup ("Json_gen init failed");
                return json_buf;
              }}

            if (yajl_gen_status_ok != gen_{typename} (g, ptr, ctx, err))
              {{
                if (*err == NULL)
                    *err = strdup ("Failed to generate json");
                return json_buf;
              }}

            yajl_gen_get_buf (g, &gen_buf, &gen_len);
            if (gen_buf == NULL)
              {{
                *err = strdup ("Error to get generated json");
                return json_buf;
              }}

            json_buf = calloc (1, gen_len + 1);
            if (json_buf == NULL)
              {{
                *err = strdup ("Cannot allocate memory");
                return json_buf;
              }}
            (void) memcpy (json_buf, gen_buf, gen_len);
            json_buf[gen_len] = '\\0';

            return json_buf;
        }}
    ''', indent=0)
