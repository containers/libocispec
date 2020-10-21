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

import helpers


def append_c_code(obj, c_file, prefix):
    """
    Description: append c language code to file
    Interface: None
    History: 2019-06-17
    """
    parse_json_to_c(obj, c_file, prefix)
    make_c_free (obj, c_file, prefix)
    get_c_json(obj, c_file, prefix)


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
    c_file.write('    if (YAJL_GET_OBJECT (tree) != NULL && YAJL_GET_OBJECT_NO_CHECK(tree)->len > 0)\n')
    c_file.write('      {\n')
    c_file.write('        size_t i;\n')
    c_file.write('        size_t len = YAJL_GET_OBJECT_NO_CHECK (tree)->len;\n')
    c_file.write('        const char **keys = YAJL_GET_OBJECT_NO_CHECK (tree)->keys;\n')
    c_file.write('        yajl_val *values = YAJL_GET_OBJECT_NO_CHECK (tree)->values;\n')
    c_file.write('        ret->len = len;\n')
    c_file.write('        ret->keys = calloc (len + 1, sizeof (*ret->keys));\n')
    c_file.write('        if (ret->keys == NULL)\n')
    c_file.write('          return NULL;\n')
    c_file.write('        ret->%s = calloc (len + 1, sizeof (*ret->%s));\n' % \
                 (child.fixname, child.fixname))
    c_file.write('        if (ret->%s == NULL)\n' % child.fixname)
    c_file.write('          {\n')
    c_file.write('            return NULL;\n')
    c_file.write('          }\n')
    c_file.write('        for (i = 0; i < len; i++)\n')
    c_file.write('          {\n')
    c_file.write('            yajl_val val;\n')
    c_file.write('            const char *tmpkey = keys[i];\n')
    c_file.write('            ret->keys[i] = strdup (tmpkey ? tmpkey : "");\n')
    c_file.write('            if (ret->keys[i] == NULL)\n')
    c_file.write('              {\n')
    c_file.write("                return NULL;\n")
    c_file.write('              }\n')
    c_file.write('            val = values[i];\n')
    c_file.write('            ret->%s[i] = make_%s (val, ctx, err);\n' \
                 % (child.fixname, childname))
    c_file.write('            if (ret->%s[i] == NULL)\n' % (child.fixname))
    c_file.write('              {\n')
    c_file.write("                return NULL;\n")
    c_file.write('              }\n')
    c_file.write('        }\n')
    c_file.write('    }\n')


def parse_obj_type_array(obj, c_file, prefix, obj_typename):
    if obj.subtypobj or obj.subtyp == 'object':
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_name_substr(obj.name, prefix)
        c_file.write('    do\n')
        c_file.write('      {\n')
        c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_array);\n' \
                     % (obj.origname))
        c_file.write('        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL &&' \
                     ' YAJL_GET_ARRAY_NO_CHECK (tmp)->len > 0)\n')
        c_file.write('          {\n')
        c_file.write('            size_t i;\n')
        c_file.write('            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;\n')
        c_file.write('            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;\n')
        c_file.write('            ret->%s_len = len;\n' % (obj.fixname))
        c_file.write('            ret->%s = calloc (len + 1, sizeof (*ret->%s));\n' % \
                     (obj.fixname, obj.fixname))
        c_file.write('            if (ret->%s == NULL)\n' % obj.fixname)
        c_file.write('              {\n')
        c_file.write('                return NULL;\n')
        c_file.write('              }\n')
        if obj.doublearray:
            c_file.write('              ret->%s_item_lens = calloc ( len + 1, sizeof (size_t));\n'
                    % (obj.fixname))
            c_file.write('              if (ret->%s_item_lens == NULL)\n' % (obj.fixname))
            c_file.write('                  return NULL;\n')
        c_file.write('            for (i = 0; i < len; i++)\n')
        c_file.write('              {\n')
        c_file.write('                yajl_val val = values[i];\n')
        if obj.doublearray:
            c_file.write('                size_t j;\n')
            c_file.write('                ret->%s[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(val)->len + 1, sizeof (**ret->%s));\n'
                    % (obj.fixname, obj.fixname))
            c_file.write('                if (ret->%s[i] == NULL)\n' % obj.fixname)
            c_file.write('                    return NULL;\n')
            c_file.write('                yajl_val *items = YAJL_GET_ARRAY_NO_CHECK(val)->values;\n')
            c_file.write('                for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(val)->len; j++)\n')
            c_file.write('                  {\n')
            c_file.write('                    ret->%s[i][j] = make_%s (items[j], ctx, err);\n' \
                    % (obj.fixname, typename))
            c_file.write('                    if (ret->%s[i][j] == NULL)\n' % (obj.fixname))
            c_file.write("                        return NULL;\n")
            c_file.write('                    ret->%s_item_lens[i] += 1;\n' % (obj.fixname))
            c_file.write('                };\n')
        else:
            c_file.write('                ret->%s[i] = make_%s (val, ctx, err);\n' \
                         % (obj.fixname, typename))
            c_file.write('                if (ret->%s[i] == NULL)\n' % (obj.fixname))
            c_file.write('                  {\n')
            c_file.write("                    return NULL;\n")
            c_file.write('                }\n')
        c_file.write('            }\n')
        c_file.write('        }\n')
        c_file.write('      }\n')
        c_file.write('    while (0);\n')
    elif obj.subtyp == 'byte':
        c_file.write('    do\n')
        c_file.write('      {\n')
        c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_string);\n' \
                     % (obj.origname))
        c_file.write('        if (tmp != NULL)\n')
        c_file.write('          {\n')
        if obj.doublearray:
            c_file.write('                yajl_val *items = YAJL_GET_ARRAY_NO_CHECK(tmp)->values;\n')
            c_file.write('                ret->%s = calloc ( YAJL_GET_ARRAY_NO_CHECK(tmp)->len + 1, sizeof (*ret->%s));\n'
                    % (obj.fixname, obj.fixname))
            c_file.write('                if (ret->%s[i] == NULL)\n' % obj.fixname)
            c_file.write('                    return NULL;\n')
            c_file.write('                size_t j;\n')
            c_file.write('                for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(tmp)->len; j++)\n')
            c_file.write('                  {\n')
            c_file.write('                    char *str = YAJL_GET_STRING (itmes[j]);\n')
            c_file.write('                    ret->%s[j] = (uint8_t *)strdup (str ? str : "");\n' \
                    % obj.fixname)
            c_file.write('                    if (ret->%s[j] == NULL)\n' % (obj.fixname))
            c_file.write("                        return NULL;\n")
            c_file.write('                };\n')
        else:
            c_file.write('            char *str = YAJL_GET_STRING (tmp);\n')
            c_file.write('            ret->%s = (uint8_t *)strdup (str ? str : "");\n' \
                         % obj.fixname)
            c_file.write('            if (ret->%s == NULL)\n' % obj.fixname)
            c_file.write('              return NULL;')
            c_file.write('            ret->%s_len = str != NULL ? strlen (str) : 0;\n' \
                         % obj.fixname)
        c_file.write('        }\n')
        c_file.write('      }\n')
        c_file.write('    while (0);\n')
    else:
        c_file.write('    do\n')
        c_file.write('      {\n')
        c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_array);\n' \
                     % (obj.origname))
        c_file.write('        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL &&'  \
                     ' YAJL_GET_ARRAY_NO_CHECK (tmp)->len > 0)\n')
        c_file.write('          {\n')
        c_file.write('            size_t i;\n')
        c_file.write('            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;\n')
        c_file.write('            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;\n')
        c_file.write('            ret->%s_len = len;\n' % (obj.fixname))
        c_file.write('            ret->%s = calloc (len + 1, sizeof (*ret->%s));\n' \
                     % (obj.fixname, obj.fixname))
        c_file.write('            if (ret->%s == NULL)\n' % obj.fixname)
        c_file.write('              {\n')
        c_file.write('                return NULL;\n')
        c_file.write('              }\n')
        if obj.doublearray:
            c_file.write('              ret->%s_item_lens = calloc ( len + 1, sizeof (size_t));\n'
                    % (obj.fixname))
            c_file.write('              if (ret->%s_item_lens == NULL)\n' % (obj.fixname))
            c_file.write('                  return NULL;\n')
        c_file.write('            for (i = 0; i < len; i++)\n')
        c_file.write('              {\n')
        if obj.doublearray:
            c_file.write('                    yajl_val *items = YAJL_GET_ARRAY_NO_CHECK(values[i])->values;\n')
            c_file.write('                    ret->%s[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(values[i])->len + 1, sizeof (**ret->%s));\n'
                    % (obj.fixname, obj.fixname))
            c_file.write('                    if (ret->%s[i] == NULL)\n' % obj.fixname)
            c_file.write('                        return NULL;\n')
            c_file.write('                    size_t j;\n')
            c_file.write('                    for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(values[i])->len; j++)\n')
            c_file.write('                      {\n')
            read_val_generator(c_file, 5, 'items[j]', \
                                "ret->%s[i][j]" % obj.fixname, obj.subtyp, obj.origname, obj_typename)
            c_file.write('                        ret->%s_item_lens[i] += 1;\n' % (obj.fixname))
            c_file.write('                    };\n')
        else:
            read_val_generator(c_file, 4, 'values[i]', \
                                "ret->%s[i]" % obj.fixname, obj.subtyp, obj.origname, obj_typename)
        c_file.write('              }\n')
        c_file.write('        }\n')
        c_file.write('      }\n')
        c_file.write('    while (0);\n')

def parse_obj_type(obj, c_file, prefix, obj_typename):
    """
    Description: generate c language for parse object type
    Interface: None
    History: 2019-06-17
    """
    if obj.typ == 'string':
        c_file.write('    do\n')
        c_file.write('      {\n')
        read_val_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_string)' % obj.origname, \
                             "ret->%s" % obj.fixname, obj.typ, obj.origname, obj_typename)
        c_file.write('      }\n')
        c_file.write('    while (0);\n')
    elif helpers.judge_data_type(obj.typ):
        c_file.write('    do\n')
        c_file.write('      {\n')
        read_val_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_number)' % obj.origname, \
                             "ret->%s" % obj.fixname, obj.typ, obj.origname, obj_typename)
        c_file.write('      }\n')
        c_file.write('    while (0);\n')
    elif helpers.judge_data_pointer_type(obj.typ):
        c_file.write('    do\n')
        c_file.write('      {\n')
        read_val_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_number)' % obj.origname, \
                             "ret->%s" % obj.fixname, obj.typ, obj.origname, obj_typename)
        c_file.write('      }\n')
        c_file.write('    while (0);\n')
    if obj.typ == 'boolean':
        c_file.write('    do\n')
        c_file.write('      {\n')
        read_val_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_true)' % obj.origname, \
                             "ret->%s" % obj.fixname, obj.typ, obj.origname, obj_typename)
        c_file.write('      }\n')
        c_file.write('    while (0);\n')
    if obj.typ == 'booleanPointer':
        c_file.write('    do\n')
        c_file.write('      {\n')
        read_val_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_true)' % obj.origname, \
                             "ret->%s" % obj.fixname, obj.typ, obj.origname, obj_typename)
        c_file.write('      }\n')
        c_file.write('    while (0);\n')
    elif obj.typ == 'object' or obj.typ == 'mapStringObject':
        if obj.subtypname is not None:
            typename = obj.subtypname
        else:
            typename = helpers.get_prefixed_name(obj.name, prefix)
        c_file.write(
            '    ret->%s = make_%s (get_val (tree, "%s", yajl_t_object), ctx, err);\n' \
            % (obj.fixname, typename, obj.origname))
        c_file.write("    if (ret->%s == NULL && *err != 0)\n" % obj.fixname)
        c_file.write("      {\n")
        c_file.write("        return NULL;\n")
        c_file.write("      }\n")
    elif obj.typ == 'array':
        parse_obj_type_array(obj, c_file, prefix, obj_typename)
    elif helpers.valid_basic_map_name(obj.typ):
        c_file.write('    do\n')
        c_file.write('      {\n')
        c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_object);\n' \
                     % (obj.origname))
        c_file.write('        if (tmp != NULL)\n')
        c_file.write('          {\n')
        c_file.write('            ret->%s = make_%s (tmp, ctx, err);\n' \
                     % (obj.fixname, helpers.make_basic_map_name(obj.typ)))
        c_file.write('            if (ret->%s == NULL)\n' % (obj.fixname))
        c_file.write('              {\n')
        c_file.write('                char *new_error = NULL;\n')
        c_file.write("                if (asprintf (&new_error, \"Value error for key" \
                     " '%s': %%s\", *err ? *err : \"null\") < 0)\n" % (obj.origname))
        c_file.write('                  new_error = strdup (' \
                     '"error allocating memory");\n')
        c_file.write('                free (*err);\n')
        c_file.write('                *err = new_error;\n')
        c_file.write('                return NULL;\n')
        c_file.write('            }\n')
        c_file.write('        }\n')
        c_file.write('      }\n')
        c_file.write('    while (0);\n')

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
        c_file.write('    if (ret->%s == NULL)\n' % i.fixname)
        c_file.write('      {\n')
        c_file.write('        if (asprintf (err, "Required field \'%%s\' not present", ' \
                     ' "%s") < 0)\n' % i.origname)
        c_file.write('            *err = strdup ("error allocating memory");\n')
        c_file.write("        return NULL;\n")
        c_file.write('      }\n')

    if obj.typ == 'object' and obj.children is not None:
        # O(n^2) complexity, but the objects should not really be big...
        condition = "\n                && ".join( \
            ['strcmp (tree->u.object.keys[i], "%s")' % i.origname for i in obj.children])
        c_file.write("""
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
              {
                return NULL;
              }
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
          {
            if (%s)
              {
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
        if (ctx->options & OPT_PARSE_STRICT)
          {
            if (j > 0 && ctx->errfile != NULL)
                (void) fprintf (ctx->errfile, "WARNING: unknown key found\\n");
          }
        if (ctx->options & OPT_PARSE_FULLKEY)
            ret->_residual = resi;
      }
""" % (condition))


def parse_json_to_c(obj, c_file, prefix):
    """
    Description: generate c language for parse json file
    Interface: None
    History: 2019-06-17
    """
    if not helpers.judge_complex(obj.typ):
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
    c_file.write("define_cleaner_function (%s *, free_%s)\n" % (typename, typename))
    c_file.write("%s *\nmake_%s (yajl_val tree, const struct parser_context *ctx, "\
        "parser_error *err)\n" % (typename, typename))
    c_file.write("{\n")
    c_file.write("    __auto_cleanup(free_%s) %s *ret = NULL;\n" % (typename, typename))
    c_file.write("    *err = NULL;\n")
    c_file.write("    (void) ctx;  /* Silence compiler warning.  */\n")
    c_file.write("    if (tree == NULL)\n")
    c_file.write("      return NULL;\n")
    c_file.write("    ret = calloc (1, sizeof (*ret));\n")
    c_file.write("    if (ret == NULL)\n")
    c_file.write("      return NULL;\n")
    if obj.typ == 'mapStringObject':
        parse_map_string_obj(obj, c_file, prefix, obj_typename)

    if obj.typ == 'object' or (obj.typ == 'array' and obj.subtypobj):
        parse_obj_arr_obj(obj, c_file, prefix, obj_typename)
    c_file.write('    return move_ptr (ret);\n')
    c_file.write("}\n\n")


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
    c_file.write('    size_t len = 0, i;\n')
    c_file.write("    if (ptr != NULL)\n")
    c_file.write("        len = ptr->len;\n")
    c_file.write("    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))\n")
    c_file.write('        yajl_gen_config (g, yajl_gen_beautify, 0);\n')
    c_file.write("    stat = yajl_gen_map_open ((yajl_gen) g);\n")
    c_file.write("    if (stat != yajl_gen_status_ok)\n")
    c_file.write("        GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    c_file.write('    if (len || (ptr != NULL && ptr->keys != NULL && ptr->%s != NULL))\n' \
                 % child.fixname)
    c_file.write('      {\n')
    c_file.write('        for (i = 0; i < len; i++)\n')
    c_file.write('          {\n')
    c_file.write('            char *str = ptr->keys[i] ? ptr->keys[i] : "";\n')
    c_file.write('            stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)str, strlen (str));\n')
    c_file.write("            if (stat != yajl_gen_status_ok)\n")
    c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    c_file.write('            stat = gen_%s (g, ptr->%s[i], ctx, err);\n' \
                 % (childname, child.fixname))
    c_file.write("            if (stat != yajl_gen_status_ok)\n")
    c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    c_file.write('        }\n')
    c_file.write('    }\n')
    c_file.write("    stat = yajl_gen_map_close ((yajl_gen) g);\n")
    c_file.write("    if (stat != yajl_gen_status_ok)\n")
    c_file.write("        GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    c_file.write("    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))\n")
    c_file.write('        yajl_gen_config (g, yajl_gen_beautify, 1);\n')

def get_obj_arr_obj_array(obj, c_file, prefix):
    if obj.subtypobj or obj.subtyp == 'object':
        l = len(obj.origname)
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_name_substr(obj.name, prefix)
        c_file.write('    if ((ctx->options & OPT_GEN_KEY_VALUE) || ' \
                     '(ptr != NULL && ptr->%s != NULL))\n' % obj.fixname)
        c_file.write('      {\n')
        c_file.write('        size_t len = 0, i;\n')
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("        if (ptr != NULL && ptr->%s != NULL)\n" % obj.fixname)
        c_file.write("            len = ptr->%s_len;\n" % obj.fixname)
        c_file.write("        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))\n")
        c_file.write('            yajl_gen_config (g, yajl_gen_beautify, 0);\n')
        c_file.write('        stat = yajl_gen_array_open ((yajl_gen) g);\n')
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write('        for (i = 0; i < len; i++)\n')
        c_file.write('          {\n')
        if obj.doublearray:
            c_file.write('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            c_file.write("            if (stat != yajl_gen_status_ok)\n")
            c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.write("            size_t j;\n")
            c_file.write('            for (j = 0; j < ptr->%s_item_lens[i]; j++)\n' %(obj.fixname))
            c_file.write('              {\n')
            c_file.write('                stat = gen_%s (g, ptr->%s[i][j], ctx, err);\n' \
                    % (typename, obj.fixname))
            c_file.write("                if (stat != yajl_gen_status_ok)\n")
            c_file.write("                    GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.write('            }\n')
            c_file.write('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            c_file.write('            stat = gen_%s (g, ptr->%s[i], ctx, err);\n' \
                         % (typename, obj.fixname))
            c_file.write("            if (stat != yajl_gen_status_ok)\n")
            c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write('        }\n')
        c_file.write('        stat = yajl_gen_array_close ((yajl_gen) g);\n')
        c_file.write("        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))\n")
        c_file.write('            yajl_gen_config (g, yajl_gen_beautify, 1);\n')
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write('      }\n')
    elif obj.subtyp == 'byte':
        l = len(obj.origname)
        c_file.write('    if ((ctx->options & OPT_GEN_KEY_VALUE) ||' \
                     ' (ptr != NULL && ptr->%s != NULL && ptr->%s_len))\n' \
                     % (obj.fixname, obj.fixname))
        c_file.write('      {\n')
        c_file.write('        const char *str = "";\n')
        c_file.write('        size_t len = 0;\n')
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        if obj.doublearray:
            c_file.write('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            c_file.write("            if (stat != yajl_gen_status_ok)\n")
            c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.write("        {\n")
            c_file.write("            size_t i;\n")
            c_file.write("            for (i = 0; i < ptr->%s_len; i++)\n" % (obj.fixname))
            c_file.write("              {\n")
            c_file.write("                if (ptr->%s[i] != NULL)\n" % obj.fixname)
            c_file.write("                    str = (const char *)ptr->%s[i];\n" % obj.fixname)
            c_file.write("                else ()\n")
            c_file.write("                    str = "";\n")
            c_file.write('                stat = yajl_gen_string ((yajl_gen) g, \
                    (const unsigned char *)str, strlen(str));\n')
            c_file.write("            }\n")
            c_file.write("        }\n")
            c_file.write('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            c_file.write("        if (ptr != NULL && ptr->%s != NULL)\n" % obj.fixname)
            c_file.write("          {\n")
            c_file.write("            str = (const char *)ptr->%s;\n" % obj.fixname)
            c_file.write("            len = ptr->%s_len;\n" % obj.fixname)
            c_file.write("          }\n")
            c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
    (const unsigned char *)str, len);\n')
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("      }\n")
    else:
        l = len(obj.origname)
        c_file.write('    if ((ctx->options & OPT_GEN_KEY_VALUE) || ' \
                     '(ptr != NULL && ptr->%s != NULL))\n' % obj.fixname)
        c_file.write('      {\n')
        c_file.write('        size_t len = 0, i;\n')
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("        if (ptr != NULL && ptr->%s != NULL)\n" % obj.fixname)
        c_file.write("          len = ptr->%s_len;\n" % obj.fixname)
        c_file.write("        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))\n")
        c_file.write('            yajl_gen_config (g, yajl_gen_beautify, 0);\n')
        c_file.write('        stat = yajl_gen_array_open ((yajl_gen) g);\n')
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write('        for (i = 0; i < len; i++)\n')
        c_file.write('          {\n')

        if obj.doublearray:
            typename = helpers.get_map_c_types(obj.subtyp)
            c_file.write('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            c_file.write("            if (stat != yajl_gen_status_ok)\n")
            c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.write("            size_t j;\n")
            c_file.write('            for (j = 0; j < ptr->%s_item_lens[i]; j++)\n' % obj.fixname)
            c_file.write('              {\n')
            json_value_generator(c_file, 4, "ptr->%s[i][j]" % obj.fixname, 'g', 'ctx', obj.subtyp)
            c_file.write('            }\n')
            c_file.write('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            json_value_generator(c_file, 3, "ptr->%s[i]" % obj.fixname, 'g', 'ctx', obj.subtyp)

        c_file.write('          }\n')
        c_file.write('        stat = yajl_gen_array_close ((yajl_gen) g);\n')
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))\n")
        c_file.write('            yajl_gen_config (g, yajl_gen_beautify, 1);\n')
        c_file.write('      }\n')

def get_obj_arr_obj(obj, c_file, prefix):
    """
    Description: c language generate object or array object
    Interface: None
    History: 2019-06-17
    """
    if obj.typ == 'string':
        l = len(obj.origname)
        c_file.write('    if ((ctx->options & OPT_GEN_KEY_VALUE) ||' \
                     ' (ptr != NULL && ptr->%s != NULL))\n' % obj.fixname)
        c_file.write('      {\n')
        c_file.write('        char *str = "";\n')
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("        if (ptr != NULL && ptr->%s != NULL)\n" % obj.fixname)
        c_file.write("            str = ptr->%s;\n" % obj.fixname)
        json_value_generator(c_file, 2, "str", 'g', 'ctx', obj.typ)
        c_file.write("      }\n")
    elif helpers.judge_data_type(obj.typ):
        c_file.write('    if ((ctx->options & OPT_GEN_KEY_VALUE) ||' \
                     ' (ptr != NULL && ptr->%s_present))\n' % obj.fixname)
        c_file.write('      {\n')
        if obj.typ == 'double':
            numtyp = 'double'
        elif obj.typ.startswith("uint") or obj.typ == 'GID' or obj.typ == 'UID':
            numtyp = 'long long unsigned int'
        else:
            numtyp = 'long long int'
        l = len(obj.origname)
        c_file.write('        %s num = 0;\n' % numtyp)
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("        if (ptr != NULL && ptr->%s)\n" % obj.fixname)
        c_file.write("            num = (%s)ptr->%s;\n" % (numtyp, obj.fixname))
        json_value_generator(c_file, 2, "num", 'g', 'ctx', obj.typ)
        c_file.write("      }\n")
    elif helpers.judge_data_pointer_type(obj.typ):
        c_file.write('    if ((ptr != NULL && ptr->%s != NULL))\n' % obj.fixname)
        c_file.write('      {\n')
        numtyp = helpers.obtain_data_pointer_type(obj.typ)
        if numtyp == "":
            return
        l = len(obj.origname)
        c_file.write('        %s num = 0;\n' % helpers.get_map_c_types(numtyp))
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("        if (ptr != NULL && ptr->%s != NULL)\n" % obj.fixname)
        c_file.write("          {\n")
        c_file.write("            num = (%s)*(ptr->%s);\n" \
                     % (helpers.get_map_c_types(numtyp), obj.fixname))
        c_file.write("          }\n")
        json_value_generator(c_file, 2, "num", 'g', 'ctx', numtyp)
        c_file.write("      }\n")
    elif obj.typ == 'boolean':
        c_file.write('    if ((ctx->options & OPT_GEN_KEY_VALUE) ||' \
                     ' (ptr != NULL && ptr->%s_present))\n' % obj.fixname)
        c_file.write('      {\n')
        c_file.write('        bool b = false;\n')
        l = len(obj.origname)
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("        if (ptr != NULL && ptr->%s)\n" % obj.fixname)
        c_file.write("            b = ptr->%s;\n" % obj.fixname)
        c_file.write("        \n")
        json_value_generator(c_file, 2, "b", 'g', 'ctx', obj.typ)
        c_file.write("      }\n")
    elif obj.typ == 'object' or obj.typ == 'mapStringObject':
        l = len(obj.origname)
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_prefixed_name(obj.name, prefix)
        c_file.write('    if ((ctx->options & OPT_GEN_KEY_VALUE) ||' \
                     ' (ptr != NULL && ptr->%s != NULL))\n' % obj.fixname)
        c_file.write("      {\n")
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write('        stat = gen_%s (g, ptr != NULL ? ptr->%s : NULL, ctx, err);\n' \
                     % (typename, obj.fixname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("      }\n")
    elif obj.typ == 'array':
        get_obj_arr_obj_array(obj, c_file, prefix)
    elif helpers.valid_basic_map_name(obj.typ):
        l = len(obj.origname)
        c_file.write('    if ((ctx->options & OPT_GEN_KEY_VALUE) || ' \
                     '(ptr != NULL && ptr->%s != NULL))\n' % obj.fixname)
        c_file.write('      {\n')
        c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
(const unsigned char *)("%s"), %d /* strlen ("%s") */);\n' % (obj.origname, l, obj.origname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write('        stat = gen_%s (g, ptr ? ptr->%s : NULL, ctx, err);\n' \
                     % (helpers.make_basic_map_name(obj.typ), obj.fixname))
        c_file.write("        if (stat != yajl_gen_status_ok)\n")
        c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("      }\n")

def get_c_json(obj, c_file, prefix):
    """
    Description: c language generate json file
    Interface: None
    History: 2019-06-17
    """
    if not helpers.judge_complex(obj.typ) or obj.subtypname:
        return
    if obj.typ == 'object' or obj.typ == 'mapStringObject':
        typename = helpers.get_prefixed_name(obj.name, prefix)
    elif obj.typ == 'array':
        typename = helpers.get_name_substr(obj.name, prefix)
        objs = obj.subtypobj
        if objs is None:
            return
    c_file.write(
        "yajl_gen_status\ngen_%s (yajl_gen g, const %s *ptr, const struct parser_context " \
        "*ctx, parser_error *err)\n" % (typename, typename))
    c_file.write("{\n")
    c_file.write("    yajl_gen_status stat = yajl_gen_status_ok;\n")
    c_file.write("    *err = NULL;\n")
    c_file.write("    (void) ptr;  /* Silence compiler warning.  */\n")
    if obj.typ == 'mapStringObject':
        get_map_string_obj(obj, c_file, prefix)
    elif obj.typ == 'object' or (obj.typ == 'array' and obj.subtypobj):
        nodes = obj.children if obj.typ == 'object' else obj.subtypobj
        if nodes is None:
            c_file.write('    if (!(ctx->options & OPT_GEN_SIMPLIFY))\n')
            c_file.write('        yajl_gen_config (g, yajl_gen_beautify, 0);\n')

        c_file.write("    stat = yajl_gen_map_open ((yajl_gen) g);\n")
        c_file.write("    if (stat != yajl_gen_status_ok)\n")
        c_file.write("        GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        for i in nodes or []:
            get_obj_arr_obj(i, c_file, prefix)
        if obj.typ == 'object':
            if obj.children is not None:
                c_file.write("    if (ptr != NULL && ptr->_residual != NULL)\n")
                c_file.write("    {\n")
                c_file.write("        stat = gen_yajl_object_residual (ptr->_residual, g, err);\n")
                c_file.write("        if (yajl_gen_status_ok != stat)\n")
                c_file.write("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
                c_file.write("    }\n")
        c_file.write("    stat = yajl_gen_map_close ((yajl_gen) g);\n")
        c_file.write("    if (stat != yajl_gen_status_ok)\n")
        c_file.write("        GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        if nodes is None:
            c_file.write('    if (!(ctx->options & OPT_GEN_SIMPLIFY))\n')
            c_file.write('        yajl_gen_config (g, yajl_gen_beautify, 1);\n')
    c_file.write('    return yajl_gen_status_ok;\n')
    c_file.write("}\n\n")


def read_val_generator(c_file, level, src, dest, typ, keyname, obj_typename):
    """
    Description: read value generateor
    Interface: None
    History: 2019-06-17
    """
    if helpers.valid_basic_map_name(typ):
        c_file.write('%syajl_val val = %s;\n' % ('    ' * level, src))
        c_file.write('%sif (val != NULL)\n' % ('    ' * level))
        c_file.write('%s  {\n' % ('    ' * level))
        c_file.write('%s%s = make_%s (val, ctx, err);\n' \
                     % ('    ' * (level + 1), dest, helpers.make_basic_map_name(typ)))
        c_file.write('%sif (%s == NULL)\n' % ('    ' * (level + 1), dest))
        c_file.write('%s  {\n' % ('    ' * (level + 1)))
        c_file.write('%s    char *new_error = NULL;\n' % ('    ' * (level + 1)))
        c_file.write("%s    if (asprintf (&new_error, \"Value error for key" \
                     " '%s': %%s\", *err ? *err : \"null\") < 0)\n" \
                     % ('    ' * (level + 1), keyname))
        c_file.write('%s        new_error = strdup ("error allocating memory");\n' \
                     % ('    ' * (level + 1)))
        c_file.write('%s    free (*err);\n' % ('    ' * (level + 1)))
        c_file.write('%s    *err = new_error;\n' % ('    ' * (level + 1)))
        c_file.write('%s    return NULL;\n' % ('    ' * (level + 1)))
        c_file.write('%s  }\n' % ('    ' * (level + 1)))
        c_file.write('%s}\n' % ('    ' * (level)))
    elif typ == 'string':
        c_file.write('%syajl_val val = %s;\n' % ('    ' * (level), src))
        c_file.write('%sif (val != NULL)\n' % ('    ' * (level)))
        c_file.write('%s  {\n' % ('    ' * (level)))
        c_file.write('%schar *str = YAJL_GET_STRING (val);\n' % ('    ' * (level + 1)))
        c_file.write('%s%s = strdup (str ? str : "");\n' % ('    ' * (level + 1), dest))
        c_file.write('%sif (%s == NULL)\n' % ('    ' * (level + 1), dest))
        c_file.write('%s  {\n' % ('    ' * (level+1)))
        c_file.write('%s    return NULL;\n' % ('    ' * (level+1)))
        c_file.write('%s  }\n' % ('    ' * (level+1)))
        c_file.write('%s  }\n' % ('    ' * level))
    elif helpers.judge_data_type(typ):
        c_file.write('%syajl_val val = %s;\n' % ('    ' * (level), src))
        c_file.write('%sif (val != NULL)\n' % ('    ' * (level)))
        c_file.write('%s  {\n' % ('    ' * (level)))
        if typ.startswith("uint") or \
                (typ.startswith("int") and typ != "integer") or typ == "double":
            c_file.write('%sint invalid = common_safe_%s (YAJL_GET_NUMBER (val), &%s);\n' \
                         % ('    ' * (level + 1), typ, dest))
        elif typ == "integer":
            c_file.write('%sint invalid = common_safe_int (YAJL_GET_NUMBER (val), (int *)&%s);\n' \
                         % ('    ' * (level + 1), dest))
        elif typ == "UID" or typ == "GID":
            c_file.write('%sint invalid = common_safe_uint (YAJL_GET_NUMBER (val),' \
                         ' (unsigned int *)&%s);\n' % ('    ' * (level + 1), dest))
        c_file.write('%sif (invalid)\n' % ('    ' * (level + 1)))
        c_file.write('%s  {\n' % ('    ' * (level + 1)))
        c_file.write('%s    if (asprintf (err, "Invalid value \'%%s\' with type \'%s\' '
                     'for key \'%s\': %%s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)\n' \
                     % ('    ' * (level + 1), typ, keyname))
        c_file.write('%s        *err = strdup ("error allocating memory");\n' \
                     % ('    ' * (level + 1)))
        c_file.write('%s    return NULL;\n' % ('    ' * (level + 1)))
        c_file.write('%s}\n' % ('    ' * (level + 1)))
        if '[' not in dest:
            c_file.write('%s%s_present = 1;\n' % ('    ' * (level + 1), dest))
        c_file.write('%s}\n' % ('    ' * (level)))
    elif helpers.judge_data_pointer_type(typ):
        num_type = helpers.obtain_data_pointer_type(typ)
        if num_type == "":
            return
        c_file.write('%syajl_val val = %s;\n' % ('    ' * (level), src))
        c_file.write('%sif (val != NULL)\n' % ('    ' * (level)))
        c_file.write('%s  {\n' % ('    ' * (level)))
        c_file.write('%s%s = calloc (1, sizeof (%s));\n' %
                     ('    ' * (level + 1), dest, helpers.get_map_c_types(num_type)))
        c_file.write('%sif (%s == NULL\n' % ('    ' * (level + 1), dest))
        c_file.write('%s    return NULL;' % ('    ' * (level + 1)))
        c_file.write('%sint invalid = common_safe_%s (YAJL_GET_NUMBER (val), %s);\n' \
                     % ('    ' * (level + 1), num_type, dest))
        c_file.write('%sif (invalid)\n' % ('    ' * (level + 1)))
        c_file.write('%s  {\n' % ('    ' * (level + 1)))
        c_file.write('%s    if (asprintf (err, "Invalid value \'%%s\' with type \'%s\' ' \
                     'for key \'%s\': %%s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)\n' \
                     % ('    ' * (level + 1), typ, keyname))
        c_file.write('%s        *err = strdup ("error allocating memory");\n' \
                     % ('    ' * (level + 1)))
        c_file.write('%s    return NULL;\n' % ('    ' * (level + 1)))
        c_file.write('%s}\n' % ('    ' * (level + 1)))
        c_file.write('%s}\n' % ('    ' * (level)))
    elif typ == 'boolean':
        c_file.write('%syajl_val val = %s;\n' % ('    ' * (level), src))
        c_file.write('%sif (val != NULL)\n' % ('    ' * (level)))
        c_file.write('%s  {\n' % ('    ' * (level)))
        c_file.write('%s%s = YAJL_IS_TRUE(val);\n' % ('    ' * (level + 1), dest))
        if '[' not in dest:
            c_file.write('%s%s_present = 1;\n' % ('    ' * (level + 1), dest))
            c_file.write('%s  }\n' % ('    ' * (level)))
            c_file.write('%selse\n' % ('    ' * (level)))
            c_file.write('%s  {\n' % ('    ' * (level)))
            c_file.write('%sval = %s;\n' % ('    ' * (level+1), src.replace('yajl_t_true', 'yajl_t_false')))
            c_file.write('%sif (val != NULL)\n' % ('    ' * (level+1)))
            c_file.write('%s  {\n' % ('    ' * (level+1)))
            c_file.write('%s%s = 0;\n' % ('    ' * (level + 2), dest))
            c_file.write('%s%s_present = 1;\n' % ('    ' * (level + 2), dest))
            c_file.write('%s  }\n' % ('    ' * (level+1)))
        c_file.write('%s  }\n' % ('    ' * (level)))
    elif typ == 'booleanPointer':
        c_file.write('%syajl_val val = %s;\n' % ('    ' * (level), src))
        c_file.write('%sif (val != NULL)\n' % ('    ' * (level)))
        c_file.write('%s  {\n' % ('    ' * (level)))
        c_file.write('%s%s = calloc (1, sizeof (bool));\n' % ('    ' * (level + 1), dest))
        c_file.write('%sif (%s == NULL\n' % ('    ' * (level + 1), dest))
        c_file.write('%s    return NULL;' % ('    ' * (level + 1)))
        c_file.write('%s*(%s) = YAJL_IS_TRUE(val);\n' % ('    ' * (level + 1), dest))
        c_file.write('%s  }\n' % ('    ' * (level)))
        c_file.write('%selse\n' % ('    ' * (level)))
        c_file.write('%s {\n' % ('    ' * (level)))
        c_file.write('%sval = get_val (tree, "%s", yajl_t_false);\n' \
                     % ('    ' * (level + 1), keyname))
        c_file.write('%sif (val != NULL)\n' % ('    ' * (level + 1)))
        c_file.write('%s  {\n' % ('    ' * (level + 1)))
        c_file.write('%s%s = calloc (1, sizeof (bool));\n' % ('    ' * (level + 2), dest))
        c_file.write('%sif (%s == NULL\n' % ('    ' * (level + 2), dest))
        c_file.write('%s  return NULL;' % ('    ' * (level + 2)))
        c_file.write('%s*(%s) = YAJL_IS_TRUE(val);\n' % ('    ' * (level + 2), dest))
        c_file.write('%s}\n' % ('    ' * (level + 1)))
        c_file.write('%s}\n' % ('    ' * (level)))


def json_value_generator(c_file, level, src, dst, ptx, typ):
    """
    Description: json value generateor
    Interface: None
    History: 2019-06-17
    """
    if helpers.valid_basic_map_name(typ):
        c_file.write('%sstat = gen_%s (%s, %s, %s, err);\n' \
                     % ('    ' * (level), helpers.make_basic_map_name(typ), dst, src, ptx))
        c_file.write("%sif (stat != yajl_gen_status_ok)\n" % ('    ' * (level)))
        c_file.write("%sGEN_SET_ERROR_AND_RETURN (stat, err);\n" % ('    ' * (level + 1)))
    elif typ == 'string':
        c_file.write('%sstat = yajl_gen_string ((yajl_gen)%s, \
(const unsigned char *)(%s), strlen (%s));\n' % ('    ' * (level), dst, src, src))
        c_file.write("%sif (stat != yajl_gen_status_ok)\n" % ('    ' * (level)))
        c_file.write("%sGEN_SET_ERROR_AND_RETURN (stat, err);\n" % ('    ' * (level + 1)))
    elif helpers.judge_data_type(typ):
        if typ == 'double':
            c_file.write('%sstat = yajl_gen_double ((yajl_gen)%s, %s);\n' \
                         % ('    ' * (level), dst, src))
        elif typ.startswith("uint") or typ == 'GID' or typ == 'UID':
            c_file.write('%sstat = map_uint (%s, %s);\n' % ('    ' * (level), dst, src))
        else:
            c_file.write('%sstat = map_int (%s, %s);\n' % ('    ' * (level), dst, src))
        c_file.write("%sif (stat != yajl_gen_status_ok)\n" % ('    ' * (level)))
        c_file.write("%sGEN_SET_ERROR_AND_RETURN (stat, err);\n" \
                     % ('    ' * (level + 1)))
    elif typ == 'boolean':
        c_file.write('%sstat = yajl_gen_bool ((yajl_gen)%s, (int)(%s));\n' \
                     % ('    ' * (level), dst, src))
        c_file.write("%sif (stat != yajl_gen_status_ok)\n" % ('    ' * (level)))
        c_file.write("%sGEN_SET_ERROR_AND_RETURN (stat, err);\n" % ('    ' * (level + 1)))

def make_c_array_free (i, c_file, prefix):
    if helpers.valid_basic_map_name(i.subtyp):
        free_func = helpers.make_basic_map_name(i.subtyp)
        c_file.write("    if (ptr->%s != NULL)\n" % i.fixname)
        c_file.write("      {\n" % i.fixname)
        c_file.write("        size_t i;\n")
        c_file.write("        for (i = 0; i < ptr->%s_len; i++)\n" % i.fixname)
        c_file.write("          {\n" % i.fixname)
        c_file.write("            if (ptr->%s[i] != NULL)\n" % (i.fixname))
        c_file.write("              {\n")
        c_file.write("                free_%s (ptr->%s[i]);\n" % (free_func, i.fixname))
        c_file.write("                ptr->%s[i] = NULL;\n" % (i.fixname))
        c_file.write("              }\n")
        c_file.write("          }\n")
        c_file.write("        free (ptr->%s);\n" % (i.fixname))
        c_file.write("        ptr->%s = NULL;\n" % (i.fixname))
        c_file.write("      }\n")
    elif i.subtyp == 'string':
        c_file_str(c_file, i)
    elif not helpers.judge_complex(i.subtyp):
        c_file.write("   {\n")
        if i.doublearray:
            c_file.write("            size_t i;\n")
            c_file.write("            for (i = 0; i < ptr->%s_len; i++)\n" % i.fixname)
            c_file.write("              {\n")
            c_file.write("                free(ptr->%s[i]);\n" % (i.fixname))
            c_file.write("                ptr->%s[i] = NULL;\n" % (i.fixname))
            c_file.write("            }\n")
        c_file.write("        free (ptr->%s);\n" % (i.fixname))
        c_file.write("        ptr->%s = NULL;\n" % (i.fixname))
        c_file.write("    }\n")
    elif i.subtyp == 'object' or i.subtypobj is not None:
        if i.subtypname is not None:
            free_func = i.subtypname
        else:
            free_func = helpers.get_name_substr(i.name, prefix)
        c_file.write("    if (ptr->%s != NULL)\n" % i.fixname)
        c_file.write("      {\n")
        c_file.write("        size_t i;\n")
        c_file.write("        for (i = 0; i < ptr->%s_len; i++) {\n" % i.fixname)

        if i.doublearray:
            c_file.write("          size_t j;\n");
            c_file.write("          for (j = 0; j < ptr->%s_item_lens[i]; j++)\n" % i.fixname);
            c_file.write("            {\n");
            c_file.write("              free_%s (ptr->%s[i][j]);\n" % (free_func, i.fixname))
            c_file.write("              ptr->%s[i][j] = NULL;\n" % i.fixname);
            c_file.write("          }\n");
            c_file.write("        free (ptr->%s[i]);\n" % i.fixname)
            c_file.write("        ptr->%s[i] = NULL;\n" % (i.fixname))
        else:
            c_file.write("          if (ptr->%s[i] != NULL)\n" % (i.fixname))
            c_file.write("            {\n")
            c_file.write("              free_%s (ptr->%s[i]);\n" % (free_func, i.fixname))
            c_file.write("              ptr->%s[i] = NULL;\n" % (i.fixname))
            c_file.write("            }\n")
        c_file.write("      }\n")

        c_file.write("        free (ptr->%s);\n" % i.fixname)
        c_file.write("        ptr->%s = NULL;\n" % (i.fixname))
        c_file.write("      }\n")
    c_typ = helpers.obtain_pointer(i.name, i.subtypobj, prefix)
    if c_typ == "":
        return True
    if i.subobj is not None:
        c_typ = c_typ + "_element"
    c_file.write("    free_%s (ptr->%s);\n" % (c_typ, i.fixname))
    c_file.write("    ptr->%s = NULL;\n" % (i.fixname))
    return False

def make_c_free (obj, c_file, prefix):
    """
    Description: generate c free function
    Interface: None
    History: 2019-06-17
    """
    if not helpers.judge_complex(obj.typ) or obj.subtypname:
        return
    typename = helpers.get_prefixed_name(obj.name, prefix)
    case = obj.typ
    result = {'mapStringObject': lambda x: [], 'object': lambda x: x.children,
              'array': lambda x: x.subtypobj}[case](obj)
    objs = result
    if obj.typ == 'array':
        if objs is None:
            return
        else:
            typename = helpers.get_name_substr(obj.name, prefix)
    c_file.write("void\nfree_%s (%s *ptr)\n" % (typename, typename))
    c_file.write("{\n")
    c_file.write("    if (ptr == NULL)\n")
    c_file.write("        return;\n")
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
            c_file.write("    free_%s (ptr->%s);\n" % (free_func, i.fixname))
            c_file.write("    ptr->%s = NULL;\n" % (i.fixname))
        if i.typ == 'mapStringObject':
            if i.subtypname:
                free_func = i.subtypname
            else:
                free_func = helpers.get_prefixed_name(i.name, prefix)
            c_file.write("    free_%s (ptr->%s);\n" % (free_func, i.fixname))
            c_file.write("    ptr->%s = NULL;\n" % (i.fixname))
        elif i.typ == 'array':
            if make_c_array_free (i, c_file, prefix):
                continue
        else:
            typename = helpers.get_prefixed_name(i.name, prefix)
            if i.typ == 'string' or i.typ == 'booleanPointer' or \
                    helpers.judge_data_pointer_type(i.typ):
                c_file.write("    free (ptr->%s);\n" % (i.fixname))
                c_file.write("    ptr->%s = NULL;\n" % (i.fixname))
            elif i.typ == 'object':
                if i.subtypname is not None:
                    typename = i.subtypname
                c_file.write("    if (ptr->%s != NULL)\n" % (i.fixname))
                c_file.write("      {\n")
                c_file.write("        free_%s (ptr->%s);\n" % (typename, i.fixname))
                c_file.write("        ptr->%s = NULL;\n" % (i.fixname))
                c_file.write("      }\n")
    if obj.typ == 'object':
        if obj.children is not None:
            c_file.write("    yajl_tree_free (ptr->_residual);\n")
            c_file.write("    ptr->_residual = NULL;\n")
    c_file.write("    free (ptr);\n")
    c_file.write("}\n\n")


def c_file_map_str(c_file, child, childname):
    """
    Description: generate c code for map string
    Interface: None
    History: 2019-10-31
    """
    c_file.write("    if (ptr->keys != NULL && ptr->%s != NULL)\n" % child.fixname)
    c_file.write("      {\n")
    c_file.write("        size_t i;\n")
    c_file.write("        for (i = 0; i < ptr->len; i++)\n")
    c_file.write("          {\n")
    c_file.write("            free (ptr->keys[i]);\n")
    c_file.write("            ptr->keys[i] = NULL;\n")
    c_file.write("            free_%s (ptr->%s[i]);\n" % (childname, child.fixname))
    c_file.write("            ptr->%s[i] = NULL;\n" % (child.fixname))
    c_file.write("          }\n")
    c_file.write("        free (ptr->keys);\n")
    c_file.write("        ptr->keys = NULL;\n")
    c_file.write("        free (ptr->%s);\n" % (child.fixname))
    c_file.write("        ptr->%s = NULL;\n" % (child.fixname))
    c_file.write("      }\n")

def c_file_str(c_file, i):
    """
    Description: generate c code template
    Interface: None
    History: 2019-10-31
    """
    c_file.write("    if (ptr->%s != NULL)\n" % i.fixname)
    c_file.write("      {\n")
    c_file.write("        size_t i;\n")
    c_file.write("        for (i = 0; i < ptr->%s_len; i++)\n" % i.fixname)
    c_file.write("          {\n")
    if i.doublearray:
        c_file.write("            size_t j;\n")
        c_file.write("            for (j = 0; j < ptr->%s_item_lens[i]; j++)\n" % (i.fixname))
        c_file.write("              {\n")
        c_file.write("                free(ptr->%s[i][j]);\n" % (i.fixname))
        c_file.write("                ptr->%s[i][j] = NULL;\n" % (i.fixname))
        c_file.write("            }\n")
    c_file.write("            if (ptr->%s[i] != NULL)\n" % (i.fixname))
    c_file.write("              {\n")
    c_file.write("                free (ptr->%s[i]);\n" % (i.fixname))
    c_file.write("                ptr->%s[i] = NULL;\n" % (i.fixname))
    c_file.write("              }\n")
    c_file.write("          }\n")
    c_file.write("        free (ptr->%s);\n" % (i.fixname))
    c_file.write("        ptr->%s = NULL;\n" % (i.fixname))
    c_file.write("    }\n")


def src_reflect(structs, schema_info, c_file, root_typ):
    """
    Description: reflect code
    Interface: None
    History: 2019-06-17
    """
    c_file.write("// Generated from %s. Do not edit!\n" \
                 % (schema_info.name.basename))
    c_file.write("#ifndef _GNU_SOURCE\n")
    c_file.write("#define _GNU_SOURCE\n")
    c_file.write("#endif\n")
    c_file.write('#include <string.h>\n')
    c_file.write('#include <read-file.h>\n')
    c_file.write('#include "%s"\n\n' % schema_info.header.basename)
    c_file.write('#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)\n')
    c_file.write('#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)\n')
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

    c_file.write("""\n
define_cleaner_function (%s *, free_%s)\n
%s
*make_%s (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_%s) %s *ptr = NULL;
    size_t i, alen;
    if (tree == NULL || err == NULL || YAJL_GET_ARRAY (tree) == NULL)
      return NULL;
    *err = NULL;
    alen = YAJL_GET_ARRAY_NO_CHECK (tree)->len;
    if (alen == 0)
      return NULL;
    ptr = calloc (1, sizeof (%s));
    if (ptr == NULL)
      return NULL;
    ptr->items = calloc (alen + 1, sizeof(*ptr->items));
    if (ptr->items == NULL)
      return NULL;
    ptr->len = alen;
""" % (typename, typename, typename, typename, typename, typename, typename))

    if obj.doublearray:
        c_file.write('    ptr->subitem_lens = calloc ( alen + 1, sizeof (size_t));\n')
        c_file.write('    if (ptr->subitem_lens == NULL)\n')
        c_file.write('        return NULL;')

    c_file.write("""\n
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
            c_file.write('        size_t j;\n')
            c_file.write('        ptr->items[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(work)->len + 1, sizeof (**ptr->items));\n')
            c_file.write('        if (ptr->items[i] == NULL)\n')
            c_file.write('           return NULL;\n')
            c_file.write('        yajl_val *tmps = YAJL_GET_ARRAY_NO_CHECK(work)->values;\n')
            c_file.write('        for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(work)->len; j++)\n')
            c_file.write('          {\n')
            c_file.write('              ptr->items[i][j] = make_%s (tmps[j], ctx, err);\n' \
                    % (subtypename))
            c_file.write('              if (ptr->items[i][j] == NULL)\n')
            c_file.write("                  return NULL;\n")
            c_file.write('              ptr->subitem_lens[i] += 1;\n')
            c_file.write('          };\n')
        else:
            c_file.write('        ptr->items[i] = make_%s (work, ctx, err);\n' \
                         % (subtypename))
            c_file.write('        if (ptr->items[i] == NULL)\n')
            c_file.write("            return NULL;\n")
    elif obj.subtyp == 'byte':
        if obj.doublearray:
            c_file.write('        char *str = YAJL_GET_STRING (work);\n')
            c_file.write('        ptr->items[j] = (uint8_t *)strdup (str ? str : "");\n')
            c_file.write('        if (ptr->items[j] == NULL)\n')
            c_file.write("            return NULL;\n")
        else:
            c_file.write('        char *str = YAJL_GET_STRING (tree);\n')
            c_file.write('        memcpy(ptr->items, str ? str : "", strlen(str ? str : ""));\n')
            c_file.write('        break;\n')
    else:
        if obj.doublearray:
            c_file.write('        ptr->items[i] = calloc ( YAJL_GET_ARRAY_NO_CHECK(work)->len + 1, sizeof (**ptr->items));\n')
            c_file.write('        if (ptr->items[i] == NULL)\n')
            c_file.write('            return NULL;\n')
            c_file.write('        size_t j;\n')
            c_file.write('        yajl_val *tmps = YAJL_GET_ARRAY_NO_CHECK(work)->values;\n')
            c_file.write('        for (j = 0; j < YAJL_GET_ARRAY_NO_CHECK(work)->len; j++)\n')
            c_file.write('          {\n')
            read_val_generator(c_file, 3, 'tmps[j]', \
                                "ptr->items[i][j]", obj.subtyp, obj.origname, c_typ)
            c_file.write('            ptr->subitem_lens[i] += 1;\n')
            c_file.write('          };\n')
        else:
            read_val_generator(c_file, 2, 'work', \
                                "ptr->items[i]", obj.subtyp, obj.origname, c_typ)

    c_file.write("""\n
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

    c_file.write("""\n
void free_%s (%s *ptr)
{
    size_t i;

    if (ptr == NULL)
        return;

    for (i = 0; i < ptr->len; i++)
      {
""" % (typename, typename))

    if helpers.valid_basic_map_name(obj.subtyp):
        free_func = helpers.make_basic_map_name(obj.subtyp)
        c_file.write("        if (ptr->items[i] != NULL)\n")
        c_file.write("          {\n")
        c_file.write("            free_%s (ptr->items[i]);\n" % (free_func))
        c_file.write("            ptr->items[i] = NULL;\n")
        c_file.write("          }\n")
    elif obj.subtyp == 'string':
        if obj.doublearray:
            c_file.write("    size_t j;\n")
            c_file.write("    for (j = 0; j < ptr->subitem_lens[i]; j++);\n")
            c_file.write("    {\n")
            c_file.write("       free(ptr->items[i][j]);\n")
            c_file.write("       ptr->items[i][j] = NULL;\n")
            c_file.write("    }\n")
            c_file.write("    free(ptr->items[i]);\n")
            c_file.write("    ptr->items[i] = NULL;\n")
        else:
            c_file.write("    free(ptr->items[i]);\n")
            c_file.write("    ptr->items[i] = NULL;\n")
    elif not helpers.judge_complex(obj.subtyp):
        if obj.doublearray:
            c_file.write("    free(ptr->items[i]);\n")
            c_file.write("    ptr->items[i] = NULL;\n")
    elif obj.subtyp == 'object' or obj.subtypobj is not None:
        if obj.subtypname is not None:
            free_func = obj.subtypname
        else:
            free_func = helpers.get_name_substr(obj.name, prefix)

        if obj.doublearray:
            c_file.write("          size_t j;\n");
            c_file.write("          for (j = 0; j < ptr->subitem_lens[i]; j++)\n");
            c_file.write("            {\n");
            c_file.write("              free_%s (ptr->items[i][j]);\n" % (free_func))
            c_file.write("              ptr->items[i][j] = NULL;\n");
            c_file.write("            }\n");
        else:
            c_file.write("              free_%s (ptr->items[i]);\n" % (free_func))
            c_file.write("              ptr->items[i] = NULL;\n")

    c_file.write("""
      }
""")

    c_typ = helpers.obtain_pointer(obj.name, obj.subtypobj, prefix)
    if c_typ != "":
        if obj.subobj is not None:
            c_typ = c_typ + "_element"
        c_file.write("    free_%s (ptr->items);\n" % (c_typ))
        c_file.write("    ptr->items = NULL;\n")
        return
    else:
        c_file.write("""
    free(ptr->items);
    ptr->items = NULL;
""")

    c_file.write("""\n
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

    c_file.write("""\n
yajl_gen_status gen_%s (yajl_gen g, const %s *ptr, const struct parser_context *ctx,
                       parser_error *err)
{
    yajl_gen_status stat;
    size_t i;

    if (ptr == NULL)
        return yajl_gen_status_ok;
    *err = NULL;
""" % (typename, typename))

    if obj.subtypobj or obj.subtyp == 'object':
        c_file.write("""\n
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
        c_file.write('      {\n')
        if obj.doublearray:
            c_file.write('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            c_file.write("            if (stat != yajl_gen_status_ok)\n")
            c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.write("            size_t j;\n")
            c_file.write('            for (j = 0; j < ptr->subitem_lens[i]; j++)\n')
            c_file.write('              {\n')
            c_file.write('                stat = gen_%s (g, ptr->items[i][j], ctx, err);\n' \
                    % (subtypename))
            c_file.write("                if (stat != yajl_gen_status_ok)\n")
            c_file.write("                    GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.write('              }\n')
            c_file.write('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            c_file.write('            stat = gen_%s (g, ptr->items[i], ctx, err);\n' \
                         % (subtypename))
            c_file.write("            if (stat != yajl_gen_status_ok)\n")
            c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.write("""\n
            }
      }
    stat = yajl_gen_array_close ((yajl_gen) g);
""")
    elif obj.subtyp == 'byte':
        c_file.write('    {\n')
        c_file.write('            const char *str = NULL;\n')
        if obj.doublearray:
            c_file.write('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            c_file.write("            if (stat != yajl_gen_status_ok)\n")
            c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.write("            {\n")
            c_file.write("                size_t i;\n")
            c_file.write("                for (i = 0; i < ptr->len; i++)\n")
            c_file.write("                 {\n")
            c_file.write("                    if (ptr->items[i] != NULL)\n")
            c_file.write("                        str = (const char *)ptr->items[i];\n")
            c_file.write("                    else ()\n")
            c_file.write("                        str = "";\n")
            c_file.write('                    stat = yajl_gen_string ((yajl_gen) g, \
                    (const unsigned char *)str, strlen(str));\n')
            c_file.write("                 }\n")
            c_file.write("            }\n")
            c_file.write('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            c_file.write("        if (ptr != NULL && ptr->items != NULL)\n")
            c_file.write("          {\n")
            c_file.write("            str = (const char *)ptr->items;\n")
            c_file.write("          }\n")
            c_file.write('        stat = yajl_gen_string ((yajl_gen) g, \
    (const unsigned char *)str, ptr->len);\n')
        c_file.write('    }\n')
    else:
        c_file.write("""\n
    stat = yajl_gen_array_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    for (i = 0; i < ptr->len; i++)
      {
""")
        c_file.write('        {\n')
        if obj.doublearray:
            c_file.write('            stat = yajl_gen_array_open ((yajl_gen) g);\n')
            c_file.write("            if (stat != yajl_gen_status_ok)\n")
            c_file.write("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.write("            size_t j;\n")
            c_file.write('            for (j = 0; j < ptr->subitem_lens[i]; j++)\n')
            c_file.write('              {\n')
            json_value_generator(c_file, 4, "ptr->items[i][j]", 'g', 'ctx', obj.subtyp)
            c_file.write('            }\n')
            c_file.write('            stat = yajl_gen_array_close ((yajl_gen) g);\n')
        else:
            json_value_generator(c_file, 3, "ptr->items[i]", 'g', 'ctx', obj.subtyp)

        c_file.write("""\n
            }
      }
    stat = yajl_gen_array_close ((yajl_gen) g);
""")


    c_file.write("""\n
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

    c_file.write("""
%s *
%s_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)
{
    %s *ptr = NULL;
    size_t filesize;
    __auto_free char *content = NULL;

    if (filename == NULL || err == NULL)
      return NULL;

    *err = NULL;
    content = read_file (filename, &filesize);
    if (content == NULL)
      {
        if (asprintf (err, "cannot read the file: %%s", filename) < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }
    ptr = %s_parse_data (content, ctx, err);
    return ptr;
}
""" % (typename, typename, typename, typename))

    c_file.write("""
%s *
%s_parse_file_stream (FILE *stream, const struct parser_context *ctx, parser_error *err)
{
    %s *ptr = NULL;
    size_t filesize;
    __auto_free char *content = NULL ;

    if (stream == NULL || err == NULL)
      return NULL;

    *err = NULL;
    content = fread_file (stream, &filesize);
    if (content == NULL)
      {
        *err = strdup ("cannot read the file");
        return NULL;
      }
    ptr = %s_parse_data (content, ctx, err);
    return ptr;
}
""" % (typename, typename, typename, typename))

    c_file.write("""
define_cleaner_function (yajl_val, yajl_tree_free)

%s *
%s_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)
{
    %s *ptr = NULL;
    __auto_cleanup(yajl_tree_free) yajl_val tree;
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
        if (asprintf (err, "cannot parse the data: %%s", errbuf) < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }
    ptr = make_%s (tree, ctx, err);
    return ptr;
}
""" % (typename, typename, typename, typename))

    c_file.write("""\nstatic void\ncleanup_yajl_gen (yajl_gen g)
{
    if (!g)
      return;
    yajl_gen_clear (g);
    yajl_gen_free (g);
}

define_cleaner_function (yajl_gen, cleanup_yajl_gen)

""")

    c_file.write("""
char *
%s_generate_json (const %s *ptr, const struct parser_context *ctx, parser_error *err)
{
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
      }

    if (yajl_gen_status_ok != gen_%s (g, ptr, ctx, err))
      {
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
""" % (typename, typename, typename))
