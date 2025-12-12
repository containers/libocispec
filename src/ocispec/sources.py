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
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'get_val (tree, "{obj.origname}", yajl_t_string)', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    elif helpers.judge_data_type(obj.typ):
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'get_val (tree, "{obj.origname}", yajl_t_number)', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    elif helpers.judge_data_pointer_type(obj.typ):
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'get_val (tree, "{obj.origname}", yajl_t_number)', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    if obj.typ == 'boolean':
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'get_val (tree, "{obj.origname}", yajl_t_true)', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    if obj.typ == 'booleanPointer':
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'get_val (tree, "{obj.origname}", yajl_t_true)', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    elif obj.typ == 'object' or obj.typ == 'mapStringObject':
        if obj.subtypname is not None:
            typename = obj.subtypname
        else:
            typename = helpers.get_prefixed_name(obj.name, prefix)
        c_file.append(
            f'    ret->{obj.fixname} = make_{typename} (get_val (tree, "{obj.origname}", yajl_t_object), ctx, err);\n')
        c_file.append(f"    if (ret->{obj.fixname} == NULL && *err != 0)\n")
        c_file.append("      return NULL;\n")
    elif obj.typ == 'array':
        parse_obj_type_array(obj, c_file, prefix, obj_typename)
    elif helpers.valid_basic_map_name(obj.typ):
        c_file.append('    do\n')
        c_file.append('      {\n')
        c_file.append(f'        yajl_val tmp = get_val (tree, "{obj.origname}", yajl_t_object);\n')
        c_file.append('        if (tmp != NULL)\n')
        c_file.append('          {\n')
        c_file.append(f'            ret->{obj.fixname} = make_{helpers.make_basic_map_name(obj.typ)} (tmp, ctx, err);\n')
        c_file.append(f'            if (ret->{obj.fixname} == NULL)\n')
        c_file.append('              {\n')
        c_file.append('                char *new_error = NULL;\n')
        c_file.append(f"                if (asprintf (&new_error, \"Value error for key '{obj.origname}': %s\", *err ? *err : \"null\") < 0)\n")
        c_file.append('                  new_error = strdup (' \
                     '"error allocating memory");\n')
        c_file.append('                free (*err);\n')
        c_file.append('                *err = new_error;\n')
        c_file.append('                return NULL;\n')
        c_file.append('              }\n')
        c_file.append('          }\n')
        c_file.append('      }\n')
        c_file.append('    while (0);\n')

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
        c_file.append(f'    if (ret->{i.fixname} == NULL)\n')
        c_file.append('      {\n')
        c_file.append(f'        if (asprintf (err, "Required field \'%s\' not present",  "{i.origname}") < 0)\n')
        c_file.append('            *err = strdup ("error allocating memory");\n')
        c_file.append("        return NULL;\n")
        c_file.append('      }\n')

    if obj.typ == 'object' and obj.children is not None:
        # O(n^2) complexity, but the objects should not really be big...
        condition = "\n                && ".join( \
            [f'strcmp (tree->u.object.keys[i], "{i.origname}")' for i in obj.children])
        c_file.append("""
    if (tree->type == yajl_t_object)
      {
        size_t i;
        size_t j = 0;
        size_t cnt = tree->u.object.len;
        yajl_val resi = NULL;

        if (ctx->options & OPT_PARSE_FULLKEY)
          {
            resi = calloc (1, sizeof(*tree));
            if (resi == NULL)
              return NULL;

            resi->type = yajl_t_object;
            resi->u.object.keys = calloc (cnt, sizeof (const char *));
            if (resi->u.object.keys == NULL)
              {
                yajl_tree_free (resi);
                return NULL;
              }
            resi->u.object.values = calloc (cnt, sizeof (yajl_val));
            if (resi->u.object.values == NULL)
              {
                yajl_tree_free (resi);
                return NULL;
              }
          }

        for (i = 0; i < tree->u.object.len; i++)
          {\n""" \
            f"            if ({condition})" \
           """{
                if (ctx->options & OPT_PARSE_FULLKEY)
                  {
                    resi->u.object.keys[j] = tree->u.object.keys[i];
                    tree->u.object.keys[i] = NULL;
                    resi->u.object.values[j] = tree->u.object.values[i];
                    tree->u.object.values[i] = NULL;
                    resi->u.object.len++;
                  }
                j++;
              }
          }

        if ((ctx->options & OPT_PARSE_STRICT) && j > 0 && ctx->errfile != NULL)
          (void) fprintf (ctx->errfile, "WARNING: unknown key found\\n");

        if (ctx->options & OPT_PARSE_FULLKEY)
          ret->_residual = resi;
      }
""")


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
    c_file.append(f"define_cleaner_function ({typename} *, free_{typename})\n")
    c_file.append(f"{typename} *\nmake_{typename} (yajl_val tree, const struct parser_context *ctx, parser_error *err)\n")
    c_file.append("{\n")
    c_file.append(f"    __auto_cleanup(free_{typename}) {typename} *ret = NULL;\n")
    c_file.append("    *err = NULL;\n")
    c_file.append("    (void) ctx;  /* Silence compiler warning.  */\n")
    c_file.append("    if (tree == NULL)\n")
    c_file.append("      return NULL;\n")
    c_file.append("    ret = calloc (1, sizeof (*ret));\n")
    c_file.append("    if (ret == NULL)\n")
    c_file.append("      return NULL;\n")
    if obj.typ == 'mapStringObject':
        parse_map_string_obj(obj, c_file, prefix, obj_typename)

    if obj.typ == 'object' or (obj.typ == 'array' and obj.subtypobj):
        parse_obj_arr_obj(obj, c_file, prefix, obj_typename)
    c_file.append('    return move_ptr (ret);\n')
    c_file.append("}\n\n")


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

    emit(c_file, f'''
        size_t len = 0, i;
        if (ptr != NULL)
            len = ptr->len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_map_open ((yajl_gen) g);
    ''', indent=1)

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
        stat = yajl_gen_map_close ((yajl_gen) g);
    ''', indent=2)

    check_gen_status(c_file, indent=1)

    emit(c_file, '''
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
    ''', indent=1)

def get_obj_arr_obj_array(obj, c_file, prefix):
    if obj.subtypobj or obj.subtyp == 'object':
        l = len(obj.origname)
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_name_substr(obj.name, prefix)

        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                size_t len = 0, i;
                stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{obj.origname}"), {int(l)} /* strlen ("{obj.origname}") */);
        ''', indent=1)

        check_gen_status(c_file, indent=2)

        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                    len = ptr->{obj.fixname}_len;
                if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
                    yajl_gen_config (g, yajl_gen_beautify, 0);
                stat = yajl_gen_array_open ((yajl_gen) g);
        ''', indent=2)

        check_gen_status(c_file, indent=2)

        emit(c_file, '''
                for (i = 0; i < len; i++)
                  {
        ''', indent=2)

        if obj.doublearray:
            emit(c_file, '''
                    stat = yajl_gen_array_open ((yajl_gen) g);
            ''', indent=3)
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
                    stat = yajl_gen_array_close ((yajl_gen) g);
            ''', indent=4)
        else:
            emit(c_file, f'''
                    stat = gen_{typename} (g, ptr->{obj.fixname}[i], ctx, err);
            ''', indent=3)
            check_gen_status(c_file, indent=3)

        emit(c_file, '''
                  }
                stat = yajl_gen_array_close ((yajl_gen) g);
                if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
                    yajl_gen_config (g, yajl_gen_beautify, 1);
        ''', indent=2)

        check_gen_status(c_file, indent=2)

        emit(c_file, '''
              }
        ''', indent=1)
    elif obj.subtyp == 'byte':
        l = len(obj.origname)
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL && ptr->{obj.fixname}_len))
              {{
                const char *str = "";
                size_t len = 0;
                stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{obj.origname}"), {l} /* strlen ("{obj.origname}") */);
        ''', indent=1)

        check_gen_status(c_file, indent=2)

        if obj.doublearray:
            emit(c_file, '''
                    stat = yajl_gen_array_open ((yajl_gen) g);
            ''', indent=3)
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
                    stat = yajl_gen_array_close ((yajl_gen) g);
            ''', indent=2)
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
        l = len(obj.origname)
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                size_t len = 0, i;
                stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{obj.origname}"), {l} /* strlen ("{obj.origname}") */);
        ''', indent=1)

        check_gen_status(c_file, indent=2)

        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                  len = ptr->{obj.fixname}_len;
                if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
                    yajl_gen_config (g, yajl_gen_beautify, 0);
                stat = yajl_gen_array_open ((yajl_gen) g);
        ''', indent=2)

        check_gen_status(c_file, indent=2)

        emit(c_file, '''
                for (i = 0; i < len; i++)
                  {
        ''', indent=2)

        if obj.doublearray:
            typename = helpers.get_map_c_types(obj.subtyp)
            emit(c_file, '''
                    stat = yajl_gen_array_open ((yajl_gen) g);
            ''', indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                    size_t j;
                    for (j = 0; j < ptr->{obj.fixname}_item_lens[i]; j++)
                      {{
            ''', indent=3)
            json_value_generator(c_file, 4, f"ptr->{obj.fixname}[i][j]", 'g', 'ctx', obj.subtyp)
            emit(c_file, '''
                      }
                    stat = yajl_gen_array_close ((yajl_gen) g);
            ''', indent=4)
        else:
            json_value_generator(c_file, 3, f"ptr->{obj.fixname}[i]", 'g', 'ctx', obj.subtyp)

        emit(c_file, '''
                  }
                stat = yajl_gen_array_close ((yajl_gen) g);
        ''', indent=2)

        check_gen_status(c_file, indent=2)

        emit(c_file, '''
                if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
                    yajl_gen_config (g, yajl_gen_beautify, 1);
              }
        ''', indent=2)

def get_obj_arr_obj(obj, c_file, prefix):
    """
    Description: c language generate object or array object
    Interface: None
    History: 2019-06-17
    """
    if obj.typ == 'string':
        l = len(obj.origname)
        c_file.append(f'    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))\n' )
        c_file.append('      {\n')
        c_file.append('        char *str = "";\n')
        c_file.append(f'        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{obj.origname}"), {l} /* strlen ("{obj.origname}") */);\n')
        check_gen_status(c_file, indent=2)
        c_file.append(f"        if (ptr != NULL && ptr->{obj.fixname} != NULL)\n")
        c_file.append(f"            str = ptr->{obj.fixname};\n")
        json_value_generator(c_file, 2, "str", 'g', 'ctx', obj.typ)
        c_file.append("      }\n")
    elif helpers.judge_data_type(obj.typ):
        c_file.append(f'    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname}_present))\n')
        c_file.append('      {\n')
        if obj.typ == 'double':
            numtyp = 'double'
        elif obj.typ.startswith("uint") or obj.typ == 'GID' or obj.typ == 'UID':
            numtyp = 'long long unsigned int'
        else:
            numtyp = 'long long int'
        l = len(obj.origname)
        c_file.append(f'        {numtyp} num = 0;\n')
        c_file.append(f'        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{obj.origname}"), {l} /* strlen ("{obj.origname}") */);\n')
        check_gen_status(c_file, indent=2)
        c_file.append(f"        if (ptr != NULL && ptr->{obj.fixname})\n")
        c_file.append(f"            num = ({numtyp})ptr->{obj.fixname};\n")
        json_value_generator(c_file, 2, "num", 'g', 'ctx', obj.typ)
        c_file.append("      }\n")
    elif helpers.judge_data_pointer_type(obj.typ):
        c_file.append(f'    if ((ptr != NULL && ptr->{obj.fixname} != NULL))\n')
        c_file.append('      {\n')
        numtyp = helpers.obtain_data_pointer_type(obj.typ)
        if numtyp == "":
            return
        l = len(obj.origname)
        c_file.append(f'        {helpers.get_map_c_types(numtyp)} num = 0;\n')
        c_file.append(f'        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("{obj.origname}"), {l} /* strlen ("{obj.origname}") */);\n')
        check_gen_status(c_file, indent=2)
        c_file.append(f"        if (ptr != NULL && ptr->{obj.fixname} != NULL)\n")
        c_file.append("          {\n")
        c_file.append(f"            num = ({helpers.get_map_c_types(numtyp)})*(ptr->{obj.fixname});\n")
        c_file.append("          }\n")
        json_value_generator(c_file, 2, "num", 'g', 'ctx', numtyp)
        c_file.append("      }\n")
    elif obj.typ == 'boolean':
        c_file.append(f'    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname}_present))\n')
        c_file.append('      {\n')
        c_file.append('        bool b = false;\n')
        l = len(obj.origname)
        c_file.append(f'        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{obj.origname}"), {l} /* strlen ("{obj.origname}") */);\n')
        check_gen_status(c_file, indent=2)
        c_file.append(f"        if (ptr != NULL && ptr->{obj.fixname})\n")
        c_file.append(f"            b = ptr->{obj.fixname};\n")
        c_file.append("        \n")
        json_value_generator(c_file, 2, "b", 'g', 'ctx', obj.typ)
        c_file.append("      }\n")
    elif obj.typ == 'object' or obj.typ == 'mapStringObject':
        l = len(obj.origname)
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_prefixed_name(obj.name, prefix)
        c_file.append(f'    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))\n')
        c_file.append("      {\n")
        c_file.append(f'        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{obj.origname}"), {l} /* strlen ("{obj.origname}") */);\n')
        check_gen_status(c_file, indent=2)
        c_file.append(f'        stat = gen_{typename} (g, ptr != NULL ? ptr->{obj.fixname} : NULL, ctx, err);\n')
        check_gen_status(c_file, indent=2)
        c_file.append("      }\n")
    elif obj.typ == 'array':
        get_obj_arr_obj_array(obj, c_file, prefix)
    elif helpers.valid_basic_map_name(obj.typ):
        l = len(obj.origname)
        c_file.append(f'    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))\n')
        c_file.append('      {\n')
        c_file.append(f'        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("{obj.fixname}"), {l} /* strlen ("{obj.fixname}") */);\n')
        check_gen_status(c_file, indent=2)
        c_file.append(f'        stat = gen_{helpers.make_basic_map_name(obj.typ)} (g, ptr ? ptr->{obj.fixname} : NULL, ctx, err);\n')
        check_gen_status(c_file, indent=2)
        c_file.append("      }\n")


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
    c_file.append(
        f"yajl_gen_status\ngen_{typename} (yajl_gen g, const {typename} *ptr, const struct parser_context " \
        "*ctx, parser_error *err)\n")
    c_file.append("{\n")
    c_file.append("    yajl_gen_status stat = yajl_gen_status_ok;\n")
    c_file.append("    *err = NULL;\n")
    c_file.append("    (void) ptr;  /* Silence compiler warning.  */\n")
    if obj.typ == 'mapStringObject':
        get_map_string_obj(obj, c_file, prefix)
    elif obj.typ == 'object' or (obj.typ == 'array' and obj.subtypobj):
        nodes = obj.children if obj.typ == 'object' else obj.subtypobj
        if nodes is None:
            c_file.append('    if (!(ctx->options & OPT_GEN_SIMPLIFY))\n')
            c_file.append('        yajl_gen_config (g, yajl_gen_beautify, 0);\n')

        c_file.append("    stat = yajl_gen_map_open ((yajl_gen) g);\n")
        check_gen_status(c_file, indent=1)
        for i in nodes or []:
            get_obj_arr_obj(i, c_file, prefix)
        if obj.typ == 'object':
            if obj.children is not None:
                c_file.append("    if (ptr != NULL && ptr->_residual != NULL)\n")
                c_file.append("      {\n")
                c_file.append("        stat = gen_yajl_object_residual (ptr->_residual, g, err);\n")
                c_file.append("        if (yajl_gen_status_ok != stat)\n")
                c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
                c_file.append("      }\n")
        c_file.append("    stat = yajl_gen_map_close ((yajl_gen) g);\n")
        check_gen_status(c_file, indent=1)
        if nodes is None:
            c_file.append('    if (!(ctx->options & OPT_GEN_SIMPLIFY))\n')
            c_file.append('        yajl_gen_config (g, yajl_gen_beautify, 1);\n')
    c_file.append('    return yajl_gen_status_ok;\n')
    c_file.append("}\n\n")


def read_val_generator(c_file, level, src, dest, typ, keyname, obj_typename):
    """
    Description: read value generateor
    Interface: None
    History: 2019-06-17
    """
    if helpers.valid_basic_map_name(typ):
        c_file.append(f"{'    ' * level}yajl_val val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * level}  {{\n')
        c_file.append(f'{"    " * (level + 1)}{dest} = make_{helpers.make_basic_map_name(typ)} (val, ctx, err);\n')
        c_file.append(f"{'    ' * (level + 1)}if ({dest} == NULL)\n")
        c_file.append(f'{"    " * (level + 1)}  {{\n')
        c_file.append(f"{'    ' * (level + 1)}    char *new_error = NULL;\n")
        c_file.append(f"{'    ' * (level + 1)}    if (asprintf (&new_error, \"Value error for key '{keyname}': %s\", *err ? *err : \"null\") < 0)\n")
        c_file.append(f'{"    " * (level + 1)}        new_error = strdup ("error allocating memory");\n')
        c_file.append(f"{'    ' * (level + 1)}    free (*err);\n")
        c_file.append(f"{'    ' * (level + 1)}    *err = new_error;\n")
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f'{"    " * (level + 1)}  }}\n')
        c_file.append(f'{"    " * (level)}}}\n')
    elif typ == 'string':
        c_file.append(f"{'    ' * level}yajl_val val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f"{'    ' * (level)}  {{\n")
        c_file.append(f"{'    ' * (level + 1)}char *str = YAJL_GET_STRING (val);\n")
        c_file.append(f"{'    ' * (level + 1)}{dest} = strdup (str ? str : \"\");\n")
        c_file.append(f"{'    ' * (level + 1)}if ({dest} == NULL)\n")
        c_file.append(f"{'    ' * (level + 1)}  return NULL;\n")
        c_file.append(f'{"    " * level}  }}\n')
    elif helpers.judge_data_type(typ):
        c_file.append(f"{'    ' * level}yajl_val val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * (level)}  {{\n')
        if typ.startswith("uint") or \
                (typ.startswith("int") and typ != "integer") or typ == "double":
            c_file.append(f"{'    ' * (level + 1)}int invalid;\n")
            c_file.append(f"{'    ' * (level + 1)}if (! YAJL_IS_NUMBER (val))\n")
            c_file.append(f'{"    " * (level + 1)}  {{\n')
            c_file.append(f"{'    ' * (level + 1)}    *err = strdup (\"invalid type\");\n")
            c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
            c_file.append(f'{"    " * (level + 1)}  }}\n')
            c_file.append(f'{"    " * (level + 1)}invalid = common_safe_{typ} (YAJL_GET_NUMBER (val), &{dest});\n')
        elif typ == "integer":
            c_file.append(f"{'    ' * (level + 1)}int invalid;\n")
            c_file.append(f"{'    ' * (level + 1)}if (! YAJL_IS_NUMBER (val))\n")
            c_file.append(f'{"    " * (level + 1)}  {{\n')
            c_file.append(f"{'    ' * (level + 1)}    *err = strdup (\"invalid type\");\n")
            c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
            c_file.append(f'{"    " * (level + 1)}  }}\n')
            c_file.append(f'{"    " * (level + 1)}invalid = common_safe_int (YAJL_GET_NUMBER (val), (int *)&{dest});\n')
        elif typ == "UID" or typ == "GID":
            c_file.append(f"{'    ' * (level + 1)}int invalid;\n")
            c_file.append(f"{'    ' * (level + 1)}if (! YAJL_IS_NUMBER (val))\n")
            c_file.append(f'{"    " * (level + 1)}  {{\n')
            c_file.append(f"{'    ' * (level + 1)}    *err = strdup (\"invalid type\");\n")
            c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
            c_file.append(f'{"    " * (level + 1)}  }}\n')
            c_file.append(f'{"    " * (level + 1)}invalid = common_safe_uint (YAJL_GET_NUMBER (val), (unsigned int *)&{dest});\n')
        c_file.append(f"{'    ' * (level + 1)}if (invalid)\n")
        c_file.append(f'{"    " * (level + 1)}  {{\n')
        c_file.append(f'{"    " * (level + 1)}    if (asprintf (err, "Invalid value \'%s\' with type \'{typ}\' for key \'{keyname}\': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)\n')
        c_file.append(f'{"    " * (level + 1)}        *err = strdup ("error allocating memory");\n')
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f'{"    " * (level + 1)}}}\n')
        if '[' not in dest:
            c_file.append(f"{'    ' * (level + 1)}{dest}_present = 1;\n")
        c_file.append(f'{"    " * (level)}}}\n')
    elif helpers.judge_data_pointer_type(typ):
        num_type = helpers.obtain_data_pointer_type(typ)
        if num_type == "":
            return
        c_file.append(f"{'    ' * level}yajl_val val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * (level)}  {{\n')
        c_file.append(f'{"    " * (level + 1)}{dest} = calloc (1, sizeof ({helpers.get_map_c_types(num_type)}));\n')
        c_file.append(f"{'    ' * (level + 1)}if ({dest} == NULL)\n")
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f"{'    ' * (level + 1)}int invalid;\n")
        c_file.append(f"{'    ' * (level + 1)}if (! YAJL_IS_NUMBER (val))\n")
        c_file.append(f'{"    " * (level + 1)}  {{\n')
        c_file.append(f"{'    ' * (level + 1)}    *err = strdup (\"invalid type\");\n")
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f'{"    " * (level + 1)}}}\n')
        c_file.append(f'{"    " * (level + 1)}sinvalid = common_safe_{num_type} (YAJL_GET_NUMBER (val), {dest});\n')
        c_file.append(f"{'    ' * (level + 1)}if (invalid)\n")
        c_file.append(f'{"    " * (level + 1)}  {{\n')
        c_file.append(f'{"    " * (level + 1)}    if (asprintf (err, "Invalid value \'%s\' with type \'{typ}\' ' \
                     f'for key \'{keyname}\': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)\n')
        c_file.append(f'{"    " * (level + 1)}        *err = strdup ("error allocating memory");\n')
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f'{"    " * (level + 1)}}}\n')
        c_file.append(f'{"    " * (level)}}}\n')
    elif typ == 'boolean':
        c_file.append(f"{'    ' * level}yajl_val val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * (level)}  {{\n')
        c_file.append(f"{'    ' * (level + 1)}{dest} = YAJL_IS_TRUE(val);\n")
        if '[' not in dest:
            c_file.append(f"{'    ' * (level + 1)}{dest}_present = 1;\n")
            c_file.append(f'{"    " * (level)}  }}\n')
            c_file.append(f"{'    ' * level}else\n")
            c_file.append(f'{"    " * (level)}  {{\n')
            c_file.append(f"{'    ' * (level + 1)}val = {src.replace('yajl_t_true', 'yajl_t_false')};\n")
            c_file.append(f"{'    ' * (level + 1)}if (val != NULL)\n")
            c_file.append(f'{"    " * (level+1)}  {{\n')
            c_file.append(f"{'    ' * (level + 2)}{dest} = 0;\n")
            c_file.append(f"{'    ' * (level + 2)}{dest}_present = 1;\n")
            c_file.append(f'{"    " * (level+1)}  }}\n')
        c_file.append(f'{"    " * (level)}  }}\n')
    elif typ == 'booleanPointer':
        c_file.append(f"{'    ' * level}yajl_val val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * (level)}  {{\n')
        c_file.append(f"{'    ' * (level + 1)}{dest} = calloc (1, sizeof (bool));\n")
        c_file.append(f"{'    ' * (level + 1)}if ({dest} == NULL)\n")
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f"{'    ' * (level + 1)}*({dest}) = YAJL_IS_TRUE(val);\n")
        c_file.append(f'{"    " * (level)}  }}\n')
        c_file.append(f"{'    ' * level}else\n")
        c_file.append(f'{"    " * (level)} {{\n')
        c_file.append(f'{"    " * (level + 1)}val = get_val (tree, "{keyname}", yajl_t_false);\n')
        c_file.append(f"{'    ' * (level + 1)}if (val != NULL)\n")
        c_file.append(f'{"    " * (level + 1)}  {{\n')
        c_file.append(f"{'    ' * (level + 2)}{dest} = calloc (1, sizeof (bool));\n")
        c_file.append(f"{'    ' * (level + 2)}if ({dest} == NULL)\n")
        c_file.append(f"{'    ' * (level + 2)}  return NULL;\n")
        c_file.append(f"{'    ' * (level + 2)}*({dest}) = YAJL_IS_TRUE(val);\n")
        c_file.append(f'{"    " * (level + 1)}}}\n')
        c_file.append(f'{"    " * (level)}}}\n')


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
        else:
            typename = helpers.get_name_substr(obj.name, prefix)

    c_file.append(f"{typename} *\nclone_{typename} ({typename} *src)\n")
    c_file.append("{\n")
    c_file.append("    (void) src;  /* Silence compiler warning.  */\n")
    c_file.append(f"    __auto_cleanup(free_{typename}) {typename} *ret = NULL;\n")

    c_file.append("    ret = calloc (1, sizeof (*ret));\n")
    c_file.append("    if (ret == NULL)\n")
    c_file.append("      return NULL;\n")

    nodes = obj.children if obj.subtypobj is None else obj.subtypobj
    for i in nodes or []:
        if helpers.judge_data_type(i.typ) or i.typ == 'boolean':
            c_file.append(f"    ret->{i.fixname} = src->{i.fixname};\n")
            c_file.append(f"    ret->{i.fixname}_present = src->{i.fixname}_present;\n")
        elif i.typ == 'object':
            node_name = i.subtypname or helpers.get_prefixed_name(i.name, prefix)
            c_file.append(f"    if (src->{i.fixname})\n")
            c_file.append(f"      {{\n")
            if obj.typ != 'mapStringObject':
                c_file.append(f"        ret->{i.fixname} = clone_{node_name} (src->{i.fixname});\n")
                c_file.append(f"        if (ret->{i.fixname} == NULL)\n")
                c_file.append(f"          return NULL;\n")
            else:
                c_file.append(f"        size_t i;\n")
                c_file.append(f"        ret->{i.fixname} = calloc (src->len + 1, sizeof (*ret->{i.fixname}));\n")
                c_file.append(f"        for (i = 0; i < src->len; i++)\n")
                c_file.append("          {\n")
                c_file.append(f"             ret->{i.fixname}[i] = clone_{node_name} (src->{i.fixname}[i]);\n")
                c_file.append(f"             if (ret->{i.fixname}[i] == NULL)\n")
                c_file.append(f"               return NULL;\n")
                c_file.append("          }\n")
            c_file.append(f"      }}\n")
        elif i.typ == 'string':
            c_file.append(f"    if (src->{i.fixname})\n")
            c_file.append(f"      {{\n")
            c_file.append(f"        ret->{i.fixname} = strdup (src->{i.fixname});\n")
            c_file.append(f"        if (ret->{i.fixname} == NULL)\n")
            c_file.append(f"          return NULL;\n")
            c_file.append(f"      }}\n")
        elif i.typ == 'array':
            c_file.append(f"    if (src->{i.fixname})\n")
            c_file.append(f"      {{\n")
            c_file.append(f"        ret->{i.fixname}_len = src->{i.fixname}_len;\n")
            c_file.append(f"        ret->{i.fixname} = calloc (src->{i.fixname}_len + 1, sizeof (*ret->{i.fixname}));\n")
            c_file.append(f"        if (ret->{i.fixname} == NULL)\n")
            c_file.append(f"          return NULL;\n")
            c_file.append(f"        for (size_t i = 0; i < src->{i.fixname}_len; i++)\n")
            c_file.append(f"          {{\n")
            if helpers.judge_data_type(i.subtyp) or i.subtyp == 'boolean':
               c_file.append(f"            ret->{i.fixname}[i] = src->{i.fixname}[i];\n")
            elif i.subtyp == 'object':
                subnode_name = i.subtypname or helpers.get_prefixed_name(i.name, prefix)
                if False: # i.subtypname is not None:
                    typename = i.subtypname
                    c_file.append(f"            ret->{i.fixname}[i] = clone_{typename} (src->{i.fixname}[i]);\n")
                    c_file.append(f"            if (ret->{i.fixname}[i] == NULL)\n")
                    c_file.append(f"                return NULL;\n")
                else:
                    typename = helpers.get_prefixed_name(i.name, prefix)
                    if i.subtypname is not None:
                        typename = i.subtypname
                    maybe_element = "_element" if i.subtypname is None else ""
                    if i.doublearray:
                        c_file.append(f"            ret->{i.fixname}_item_lens[i] = src->{i.fixname}_item_lens[i];\n")
                        c_file.append(f"            ret->{i.fixname}[i] = calloc (ret->{i.fixname}_item_lens[i] + 1, sizeof (**ret->{i.fixname}[i]));\n")
                        c_file.append(f"            if (ret->{i.fixname}[i] == NULL)\n")
                        c_file.append(f"                return NULL;\n")
                        c_file.append(f"            for (size_t j = 0; j < src->{i.fixname}_item_lens[i]; j++)\n")
                        c_file.append(f"              {{\n")
                        c_file.append(f"                ret->{i.fixname}[i][j] = clone_{typename}{maybe_element} (src->{i.fixname}[i][j]);\n")
                        c_file.append(f"                if (ret->{i.fixname}[i][j] == NULL)\n")
                        c_file.append(f"                    return NULL;\n")
                        c_file.append(f"              }}\n")
                    else:
                        c_file.append(f"            ret->{i.fixname}[i] = clone_{typename}{maybe_element} (src->{i.fixname}[i]);\n")
                        c_file.append(f"            if (ret->{i.fixname}[i] == NULL)\n")
                        c_file.append(f"                return NULL;\n")

            elif i.subtyp == 'string':
                if i.doublearray:
                    c_file.append(f"            ret->{i.fixname}[i] = calloc (ret->{i.fixname}_item_lens[i] + 1, sizeof (**ret->{i.fixname}[i]));\n")
                    c_file.append(f"            if (ret->{i.fixname}[i] == NULL)\n")
                    c_file.append(f"                return NULL;\n")
                    c_file.append(f"            for (size_t j = 0; j < src->{i.fixname}_item_lens[i]; j++)\n")
                    c_file.append(f"              {{\n")
                    c_file.append(f"                ret->{i.fixname}[i][j] = strdup (src->{i.fixname}[i][j]);\n")
                    c_file.append(f"                if (ret->{i.fixname}[i][j] == NULL)\n")
                    c_file.append(f"                    return NULL;\n")
                    c_file.append(f"              }}\n")
                else:
                    c_file.append(f"            if (src->{i.fixname}[i])\n")
                    c_file.append(f"              {{\n")
                    c_file.append(f"                ret->{i.fixname}[i] = strdup (src->{i.fixname}[i]);\n")
                    c_file.append(f"                if (ret->{i.fixname}[i] == NULL)\n")
                    c_file.append(f"                  return NULL;\n")
                    c_file.append(f"              }}\n")
            else:
                raise Exception("Unimplemented type for array clone: %s (%s)" % (i.subtyp, i.subtypname))
            c_file.append(f"          }}\n")
            c_file.append(f"      }}\n")
        elif i.typ == 'mapStringString':
            c_file.append(f"    ret->{i.fixname} = clone_map_string_string (src->{i.fixname});\n")
            c_file.append(f"    if (ret->{i.fixname} == NULL)\n")
            c_file.append(f"        return NULL;\n")
        elif i.typ == 'mapStringObject':
            if i.subtypname is not None:
                subtypname = i.subtypname
                maybe_element = "_element"
            else:
                subtypname = i.children[0].subtypname
                maybe_element = ""

            c_file.append(f"    if (src->{i.fixname})\n")
            c_file.append(f"      {{\n")
            c_file.append(f"        ret->{i.fixname} = calloc (1, sizeof (*ret->{i.fixname}));\n")
            c_file.append(f"        if (ret->{i.fixname} == NULL)\n")
            c_file.append(f"            return NULL;\n")
            c_file.append(f"        ret->{i.fixname}->len = src->{i.fixname}->len;\n")
            c_file.append(f"        ret->{i.fixname}->keys = calloc (src->{i.fixname}->len + 1, sizeof (char *));\n")
            c_file.append(f"        if (ret->{i.fixname}->keys == NULL)\n")
            c_file.append(f"            return NULL;\n")
            c_file.append(f"        ret->{i.fixname}->values = calloc (src->{i.fixname}->len + 1, sizeof (*ret->{i.fixname}->values));\n")
            c_file.append(f"        if (ret->{i.fixname}->values == NULL)\n")
            c_file.append(f"            return NULL;\n")
            c_file.append(f"        for (size_t i = 0; i < ret->{i.fixname}->len; i++)\n")
            c_file.append(f"          {{\n")
            c_file.append(f"            ret->{i.fixname}->keys[i] = strdup (src->{i.fixname}->keys[i]);\n")
            c_file.append(f"            if (ret->{i.fixname}->keys[i] == NULL)\n")
            c_file.append(f"              return NULL;\n")
            c_file.append(f"            ret->{i.fixname}->values[i] = clone_{subtypname}{maybe_element} (src->{i.fixname}->values[i]);\n")
            c_file.append(f"            if (ret->{i.fixname}->values[i] == NULL)\n")
            c_file.append(f"              return NULL;\n")
            c_file.append(f"          }}\n")
            c_file.append(f"      }}\n")
        else:
            raise Exception("Unimplemented type for clone: %s" % i.typ)

    c_file.append(f"    return move_ptr (ret);\n")
    c_file.append("}\n\n")


def json_value_generator(c_file, level, src, dst, ptx, typ):
    """
    Description: json value generateor
    Interface: None
    History: 2019-06-17
    """
    if helpers.valid_basic_map_name(typ):
        c_file.append(f'{"    " * (level)}stat = gen_{helpers.make_basic_map_name(typ)} ({dst}, {src}, {ptx}, err);\n')
        c_file.append(f"{'    ' * level}if (stat != yajl_gen_status_ok)\n")
        c_file.append(f"{'    ' * (level + 1)}GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    elif typ == 'string':
        c_file.append(f'{"    " * (level)}stat = yajl_gen_string ((yajl_gen){dst}, (const unsigned char *)({src}), strlen ({src}));\n')
        c_file.append(f"{'    ' * level}if (stat != yajl_gen_status_ok)\n")
        c_file.append(f"{'    ' * (level + 1)}GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    elif helpers.judge_data_type(typ):
        if typ == 'double':
            c_file.append(f'{"    " * (level)}stat = yajl_gen_double ((yajl_gen){dst}, {src});\n')
        elif typ.startswith("uint") or typ == 'GID' or typ == 'UID':
            c_file.append(f"{'    ' * level}stat = map_uint ({dst}, {src});\n")
        else:
            c_file.append(f"{'    ' * level}stat = map_int ({dst}, {src});\n")
        c_file.append(f"{'    ' * level}if (stat != yajl_gen_status_ok)\n")
        c_file.append(f"{'    ' * (level + 1)}GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    elif typ == 'boolean':
        c_file.append(f'{"    " * (level)}stat = yajl_gen_bool ((yajl_gen){dst}, (int)({src}));\n')
        c_file.append(f"{'    ' * level}if (stat != yajl_gen_status_ok)\n")
        c_file.append(f"{'    ' * (level + 1)}GEN_SET_ERROR_AND_RETURN (stat, err);\n")

def make_c_array_free (i, c_file, prefix):
    if helpers.valid_basic_map_name(i.subtyp):
        free_func = helpers.make_basic_map_name(i.subtyp)
        c_file.append(f"    if (ptr->{i.fixname} != NULL)\n")
        c_file.append("      {\n")
        c_file.append("        size_t i;\n")
        c_file.append(f"        for (i = 0; i < ptr->{i.fixname}_len; i++)\n")
        c_file.append("          {\n")
        c_file.append(f"            if (ptr->{i.fixname}[i] != NULL)\n")
        c_file.append("              {\n")
        c_file.append(f"                free_{free_func} (ptr->{i.fixname}[i]);\n")
        c_file.append(f"                ptr->{i.fixname}[i] = NULL;\n")
        c_file.append("              }\n")
        c_file.append("          }\n")
        free_and_null(c_file, "ptr", i.fixname, indent=2)
        c_file.append("      }\n")
    elif i.subtyp == 'string':
        c_file_str(c_file, i)
    elif not helpers.is_compound_type(i.subtyp):
        c_file.append("   {\n")
        if i.doublearray:
            c_file.append("            size_t i;\n")
            c_file.append(f"            for (i = 0; i < ptr->{i.fixname}_len; i++)\n")
            c_file.append("              {\n")
            free_and_null(c_file, "ptr", f"{i.fixname}[i]", indent=4)
            c_file.append("              }\n")
            free_and_null(c_file, "ptr", f"{i.fixname}_item_lens", indent=3)
        free_and_null(c_file, "ptr", i.fixname, indent=2)
        c_file.append("    }\n")
    elif i.subtyp == 'object' or i.subtypobj is not None:
        if i.subtypname is not None:
            free_func = i.subtypname
        else:
            free_func = helpers.get_name_substr(i.name, prefix)
        c_file.append(f"    if (ptr->{i.fixname} != NULL)")
        c_file.append("      {\n")
        c_file.append("        size_t i;\n")
        c_file.append(f"        for (i = 0; i < ptr->{i.fixname}_len; i++)\n")
        c_file.append("          {\n")
        if i.doublearray:
            c_file.append("          size_t j;\n")
            c_file.append(f"          for (j = 0; j < ptr->{i.fixname}_item_lens[i]; j++)\n")
            c_file.append("            {\n")
            c_file.append(f"              free_{free_func} (ptr->{i.fixname}[i][j]);\n")
            c_file.append(f"              ptr->{i.fixname}[i][j] = NULL;\n")
            c_file.append("          }\n")
            free_and_null(c_file, "ptr", f"{i.fixname}[i]", indent=2)
        else:
            c_file.append(f"          if (ptr->{i.fixname}[i] != NULL)\n")
            c_file.append("            {\n")
            c_file.append(f"              free_{free_func} (ptr->{i.fixname}[i]);\n")
            c_file.append(f"              ptr->{i.fixname}[i] = NULL;\n")
            c_file.append("            }\n")
        c_file.append("          }\n")
        if i.doublearray:
            free_and_null(c_file, "ptr", f"{i.fixname}_item_lens", indent=2)

        free_and_null(c_file, "ptr", i.fixname, indent=2)
        c_file.append("      }\n")
    c_typ = helpers.obtain_pointer(i.name, i.subtypobj, prefix)
    if c_typ == "":
        return True
    if i.subtypname is not None:
        c_typ = c_typ + "_element"
    c_file.append(f"    free_{c_typ} (ptr->{i.fixname});\n")
    c_file.append(f"    ptr->{i.fixname} = NULL;\n")
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
        else:
            typename = helpers.get_name_substr(obj.name, prefix)
    c_file.append(f"void\nfree_{typename} ({typename} *ptr)\n")
    c_file.append("{\n")
    c_file.append("    if (ptr == NULL)\n")
    c_file.append("        return;\n")
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
            c_file.append(f"    free_{free_func} (ptr->{i.fixname});\n")
            c_file.append(f"    ptr->{i.fixname} = NULL;\n")
        if i.typ == 'mapStringObject':
            if i.subtypname:
                free_func = i.subtypname
            else:
                free_func = helpers.get_prefixed_name(i.name, prefix)
            c_file.append(f"    free_{free_func} (ptr->{i.fixname});\n")
            c_file.append(f"    ptr->{i.fixname} = NULL;\n")
        elif i.typ == 'array':
            if make_c_array_free (i, c_file, prefix):
                continue
        else:
            typename = helpers.get_prefixed_name(i.name, prefix)
            if i.typ == 'string' or i.typ == 'booleanPointer' or \
                    helpers.judge_data_pointer_type(i.typ):
                c_file.append(f"    free (ptr->{i.fixname});\n")
                c_file.append(f"    ptr->{i.fixname} = NULL;\n")
            elif i.typ == 'object':
                if i.subtypname is not None:
                    typename = i.subtypname
                c_file.append(f"    if (ptr->{i.fixname} != NULL)\n")
                c_file.append("      {\n")
                c_file.append(f"        free_{typename} (ptr->{i.fixname});\n")
                c_file.append(f"        ptr->{i.fixname} = NULL;\n")
                c_file.append("      }\n")
    if obj.typ == 'object':
        if obj.children is not None:
            c_file.append("    yajl_tree_free (ptr->_residual);\n")
            c_file.append("    ptr->_residual = NULL;\n")
    c_file.append("    free (ptr);\n")
    c_file.append("}\n\n")


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
    c_file.append(f"/* Generated from {schema_info.name.basename}. Do not edit!  */\n\n")
    c_file.append("#ifndef _GNU_SOURCE\n")
    c_file.append("#define _GNU_SOURCE\n")
    c_file.append("#endif\n")
    c_file.append('#include <string.h>\n')
    c_file.append('#include <ocispec/read-file.h>\n')
    c_file.append(f'#include "ocispec/{schema_info.header.basename}"\n\n')
    c_file.append('#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)\n')
    c_file.append('#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)\n')
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

    c_file.append(f"\ndefine_cleaner_function ({typename} *, free_{typename})\n" +
                    f"{typename}\n" +
                    f"*make_{typename} (yajl_val tree, const struct parser_context *ctx, parser_error *err)\n" +
                    "{\n" +
                    f"    __auto_cleanup(free_{typename}) {typename} *ptr = NULL;\n" +
                    f"    size_t i, alen;\n" +
                    f" "+
                    f"    (void) ctx;\n" +
                    f" "+
                    f"    if (tree == NULL || err == NULL || YAJL_GET_ARRAY (tree) == NULL)\n" +
                    f"      return NULL;\n" +
                    f"    *err = NULL;\n" +
                    f"    alen = YAJL_GET_ARRAY_NO_CHECK (tree)->len;\n" +
                    f"    if (alen == 0)\n" +
                    f"      return NULL;\n" +
                    f"    ptr = calloc (1, sizeof ({typename}));\n" +
                    f"    if (ptr == NULL)\n" +
                    f"      return NULL;\n" +
                    f"    ptr->items = calloc (alen + 1, sizeof(*ptr->items));\n" +
                    f"    if (ptr->items == NULL)\n" +
                    f"      return NULL;\n" +
                    f"    ptr->len = alen;\n"
    )

    if obj.doublearray:
        c_file.append('    ptr->subitem_lens = calloc ( alen + 1, sizeof (size_t));\n')
        c_file.append('    if (ptr->subitem_lens == NULL)\n')
        c_file.append('      return NULL;')

    c_file.append("""\n
    for (i = 0; i < alen; i++)
      {
        yajl_val work = YAJL_GET_ARRAY_NO_CHECK (tree)->values[i];
""");

    if obj.subtypobj or obj.subtyp == 'object':
        if obj.subtypname:
            subtypename = obj.subtypname
        else:
            subtypename = helpers.get_name_substr(obj.name, prefix)

        if obj.doublearray:
            c_file.append('        size_t j;\n')
            c_file.append('        ptr->items[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(work)->len + 1, sizeof (**ptr->items));\n')
            c_file.append('        if (ptr->items[i] == NULL)\n')
            c_file.append('          return NULL;\n')
            c_file.append('        yajl_val *tmps = YAJL_GET_ARRAY_NO_CHECK(work)->values;\n')
            c_file.append('        for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(work)->len; j++)\n')
            c_file.append('          {\n')
            c_file.append(f'              ptr->items[i][j] = make_{subtypename} (tmps[j], ctx, err);\n')
            c_file.append('              if (ptr->items[i][j] == NULL)\n')
            c_file.append("                return NULL;\n")
            c_file.append('              ptr->subitem_lens[i] += 1;\n')
            c_file.append('          }\n')
        else:
            c_file.append(f'        ptr->items[i] = make_{subtypename} (work, ctx, err);\n')
            c_file.append('        if (ptr->items[i] == NULL)\n')
            c_file.append("          return NULL;\n")
    elif obj.subtyp == 'byte':
        if obj.doublearray:
            c_file.append('        char *str = YAJL_GET_STRING (work);\n')
            c_file.append('        ptr->items[j] = (uint8_t *)strdup (str ? str : "");\n')
            c_file.append('        if (ptr->items[j] == NULL)\n')
            c_file.append("          return NULL;\n")
        else:
            c_file.append('        char *str = YAJL_GET_STRING (tree);\n')
            c_file.append('        memcpy(ptr->items, str ? str : "", strlen(str ? str : ""));\n')
            c_file.append('        break;\n')
    else:
        if obj.doublearray:
            c_file.append('        ptr->items[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(work)->len + 1, sizeof (**ptr->items));\n')
            c_file.append('        if (ptr->items[i] == NULL)\n')
            c_file.append('          return NULL;\n')
            c_file.append('        size_t j;\n')
            c_file.append('        yajl_val *tmps = YAJL_GET_ARRAY_NO_CHECK(work)->values;\n')
            c_file.append('        for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(work)->len; j++)\n')
            c_file.append('          {\n')
            read_val_generator(c_file, 3, 'tmps[j]', \
                                "ptr->items[i][j]", obj.subtyp, obj.origname, c_typ)
            c_file.append('            ptr->subitem_lens[i] += 1;\n')
            c_file.append('          }\n')
        else:
            read_val_generator(c_file, 2, 'work', \
                                "ptr->items[i]", obj.subtyp, obj.origname, c_typ)

    c_file.append("""\n
      }
    return move_ptr(ptr);
}
""")

def get_c_epilog_for_array_make_free(c_file, prefix, typ, obj):
    c_typ = helpers.get_prefixed_pointer(obj.name, obj.subtyp, prefix) or \
        helpers.get_map_c_types(obj.subtyp)
    if obj.subtypobj is not None:
        c_typ = helpers.get_name_substr(obj.name, prefix)
    if c_typ == "":
        return
    typename = helpers.get_top_array_type_name(obj.name, prefix)

    c_file.append(f"\n\nvoid free_{typename} ({typename} *ptr)" + """
{
    size_t i;

    if (ptr == NULL)
        return;

    for (i = 0; i < ptr->len; i++)
      {
""")

    if helpers.valid_basic_map_name(obj.subtyp):
        free_func = helpers.make_basic_map_name(obj.subtyp)
        c_file.append("        if (ptr->items[i] != NULL)\n")
        c_file.append("          {\n")
        c_file.append(f"            free_{free_func} (ptr->items[i]);\n")
        c_file.append("            ptr->items[i] = NULL;\n")
        c_file.append("          }\n")
    elif obj.subtyp == 'string':
        if obj.doublearray:
            c_file.append("        size_t j;\n")
            c_file.append("        for (j = 0; j < ptr->subitem_lens[i]; j++)\n")
            c_file.append("          {\n")
            c_file.append("            free (ptr->items[i][j]);\n")
            c_file.append("            ptr->items[i][j] = NULL;\n")
            c_file.append("          }\n")
            c_file.append("        free (ptr->items[i]);\n")
            c_file.append("        ptr->items[i] = NULL;\n")
        else:
            c_file.append("        free (ptr->items[i]);\n")
            c_file.append("        ptr->items[i] = NULL;\n")
    elif not helpers.is_compound_type(obj.subtyp):
        if obj.doublearray:
            c_file.append("        free (ptr->items[i]);\n")
            c_file.append("        ptr->items[i] = NULL;\n")
    elif obj.subtyp == 'object' or obj.subtypobj is not None:
        if obj.subtypname is not None:
            free_func = obj.subtypname
        else:
            free_func = helpers.get_name_substr(obj.name, prefix)

        if obj.doublearray:
            c_file.append("          size_t j;\n")
            c_file.append("          for (j = 0; j < ptr->subitem_lens[i]; j++)\n")
            c_file.append("            {\n")
            c_file.append(f"              free_{free_func} (ptr->items[i][j]);\n")
            c_file.append("              ptr->items[i][j] = NULL;\n")
            c_file.append("            }\n")
            c_file.append("            free (ptr->items[i]);\n")
            c_file.append("            ptr->items[i] = NULL;\n")
        else:
            c_file.append(f"          free_{free_func} (ptr->items[i]);\n")
            c_file.append("          ptr->items[i] = NULL;\n")

    c_file.append("""
      }
""")
    if obj.doublearray:
        c_file.append("    free (ptr->subitem_lens);\n")
        c_file.append("    ptr->subitem_lens = NULL;\n")

    c_typ = helpers.obtain_pointer(obj.name, obj.subtypobj, prefix)
    if c_typ != "":
        if obj.subobj is not None:
            c_typ = c_typ + "_element"
        c_file.append(f"    free_{c_typ} (ptr->items);\n")
        c_file.append("    ptr->items = NULL;\n")
        return
    else:
        c_file.append("""
    free (ptr->items);
    ptr->items = NULL;
""")

    c_file.append("""\n
    free (ptr);
}
""")

def get_c_epilog_for_array_make_gen(c_file, prefix, typ, obj):
    c_typ = helpers.get_prefixed_pointer(obj.name, obj.subtyp, prefix) or \
        helpers.get_map_c_types(obj.subtyp)
    if obj.subtypobj is not None:
        c_typ = helpers.get_name_substr(obj.name, prefix)
    if c_typ == "":
        return
    typename = helpers.get_top_array_type_name(obj.name, prefix)

    c_file.append(f"yajl_gen_status gen_{typename} (yajl_gen g, const {typename} *ptr, const struct parser_context *ctx," + """
                       parser_error *err)
{
    yajl_gen_status stat;
    size_t i;

    if (ptr == NULL)
        return yajl_gen_status_ok;
    *err = NULL;
""")

    if obj.subtypobj or obj.subtyp == 'object':
        c_file.append("""\n
    stat = yajl_gen_array_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    for (i = 0; i < ptr->len; i++)
      {
""")

        if obj.subtypname:
            subtypename = obj.subtypname
        else:
            subtypename = helpers.get_name_substr(obj.name, prefix)
        c_file.append('      {\n')
        if obj.doublearray:
            c_file.append('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            check_gen_status(c_file, indent=3)
            c_file.append("            size_t j;\n")
            c_file.append('            for (j = 0; j < ptr->subitem_lens[i]; j++)\n')
            c_file.append('              {\n')
            c_file.append(f'                stat = gen_{subtypename} (g, ptr->items[i][j], ctx, err);\n')
            c_file.append("                if (stat != yajl_gen_status_ok)\n")
            c_file.append("                    GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append('              }\n')
            c_file.append('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            c_file.append(f'            stat = gen_{subtypename} (g, ptr->items[i], ctx, err);\n')
            check_gen_status(c_file, indent=3)
        c_file.append("""\n
            }
      }
    stat = yajl_gen_array_close ((yajl_gen) g);
""")
    elif obj.subtyp == 'byte':
        c_file.append('    {\n')
        c_file.append('            const char *str = NULL;\n')
        if obj.doublearray:
            c_file.append('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            check_gen_status(c_file, indent=3)
            c_file.append("            {\n")
            c_file.append("                size_t i;\n")
            c_file.append("                for (i = 0; i < ptr->len; i++)\n")
            c_file.append("                  {\n")
            c_file.append("                    if (ptr->items[i] != NULL)\n")
            c_file.append("                        str = (const char *)ptr->items[i];\n")
            c_file.append("                    else ()\n")
            c_file.append("                        str = "";\n")
            c_file.append('                    stat = yajl_gen_string ((yajl_gen) g, \
                    (const unsigned char *)str, strlen(str));\n')
            c_file.append("                  }\n")
            c_file.append("            }\n")
            c_file.append('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            c_file.append("        if (ptr != NULL && ptr->items != NULL)\n")
            c_file.append("          {\n")
            c_file.append("            str = (const char *)ptr->items;\n")
            c_file.append("          }\n")
            c_file.append('        stat = yajl_gen_string ((yajl_gen) g, \
    (const unsigned char *)str, ptr->len);\n')
        c_file.append('    }\n')
    else:
        c_file.append("""\n
    stat = yajl_gen_array_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    for (i = 0; i < ptr->len; i++)
      {
""")
        c_file.append('        {\n')
        if obj.doublearray:
            c_file.append('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            check_gen_status(c_file, indent=3)
            c_file.append("            size_t j;\n")
            c_file.append('            for (j = 0; j < ptr->subitem_lens[i]; j++)\n')
            c_file.append('              {\n')
            json_value_generator(c_file, 4, "ptr->items[i][j]", 'g', 'ctx', obj.subtyp)
            c_file.append('            }\n')
            c_file.append('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            json_value_generator(c_file, 3, "ptr->items[i]", 'g', 'ctx', obj.subtyp)

        c_file.append("""\n
            }
      }
    stat = yajl_gen_array_close ((yajl_gen) g);
""")


    c_file.append("""\n
    if (ptr->len > 0 && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 1);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    return yajl_gen_status_ok;
}
""")

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

    c_file.append(f"\n{typename} *\n{typename}_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)"
"\n{"
    f"\n{typename} *ptr = NULL;" +
    """size_t filesize;
    __auto_free char *content = NULL;

    if (filename == NULL || err == NULL)
      return NULL;

    *err = NULL;
    content = read_file (filename, &filesize);
    if (content == NULL)
      {
        if (asprintf (err, "cannot read the file: %s", filename) < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }""" +
    f"ptr = {typename}_parse_data (content, ctx, err);" +
    """return ptr;
}
""")

    c_file.append(
f"{typename} * \n" +
f"{typename}_parse_file_stream (FILE *stream, const struct parser_context *ctx, parser_error *err)\n{{" +
    f"{typename} *ptr = NULL;"+
    """\nsize_t filesize;
    __auto_free char *content = NULL;

    if (stream == NULL || err == NULL)
      return NULL;

    *err = NULL;
    content = fread_file (stream, &filesize);
    if (content == NULL)
      {
        *err = strdup ("cannot read the file");
        return NULL;
      }\n""" +
    f"ptr = {typename}_parse_data (content, ctx, err);" +
    """return ptr;
}
""")

    c_file.append("""
define_cleaner_function (yajl_val, yajl_tree_free)
""" +
f"\n {typename} * " +
f"{typename}_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)\n {{ \n" +
    f"  {typename} *ptr = NULL;" +
    """__auto_cleanup(yajl_tree_free) yajl_val tree = NULL;
    char errbuf[1024];
    struct parser_context tmp_ctx = { 0 };

    if (jsondata == NULL || err == NULL)
      return NULL;

    *err = NULL;
    if (ctx == NULL)
     ctx = (const struct parser_context *)(&tmp_ctx);

    tree = yajl_tree_parse (jsondata, errbuf, sizeof (errbuf));
    if (tree == NULL)
      {
        if (asprintf (err, "cannot parse the data: %s", errbuf) < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }\n""" +
    f"ptr = make_{typename} (tree, ctx, err);" +
    "return ptr; \n}\n"
)

    c_file.append("""\nstatic void\ncleanup_yajl_gen (yajl_gen g)
{
    if (!g)
      return;
    yajl_gen_clear (g);
    yajl_gen_free (g);
}

define_cleaner_function (yajl_gen, cleanup_yajl_gen)

""")

    c_file.append("\n char * \n" +
f"{typename}_generate_json (const {typename} *ptr, const struct parser_context *ctx, parser_error *err)" +
"""{
    __auto_cleanup(cleanup_yajl_gen) yajl_gen g = NULL;
    struct parser_context tmp_ctx = { 0 };
    const unsigned char *gen_buf = NULL;
    char *json_buf = NULL;
    size_t gen_len = 0;

    if (ptr == NULL || err == NULL)
      return NULL;

    *err = NULL;
    if (ctx == NULL)
        ctx = (const struct parser_context *)(&tmp_ctx);

    if (!json_gen_init(&g, ctx))
      {
        *err = strdup ("Json_gen init failed");
        return json_buf;
      } \n
""" +
    f"if (yajl_gen_status_ok != gen_{typename} (g, ptr, ctx, err))" +
    """  {
        if (*err == NULL)
            *err = strdup ("Failed to generate json");
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
        *err = strdup ("Cannot allocate memory");
        return json_buf;
      }
    (void) memcpy (json_buf, gen_buf, gen_len);
    json_buf[gen_len] = '\\0';

    return json_buf;
}
""")
