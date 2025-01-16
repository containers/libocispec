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
    parse_json_objecto_c(obj, c_file, prefix)
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
    c_file.append('    if (json_object_is_type(tree, json_type_object))\n')
    c_file.append('      {\n')
    c_file.append('        size_t i;\n')
    c_file.append('        int len = json_object_object_length(tree);\n')
    c_file.append('        json_c_object_keys_values *kvobj = json_object_to_keys_values(tree);\n')
    c_file.append('        const char **keys = (const char **)kvobj->keys;\n')
    c_file.append('        json_object *values = kvobj->values;\n')
    c_file.append('        ret->len = len;\n')
    c_file.append('        ret->keys = calloc (len + 1, sizeof (*ret->keys));\n')
    c_file.append('        if (ret->keys == NULL)\n')
    c_file.append('          return NULL;\n')
    c_file.append(f'        ret->{child.fixname} = calloc (len + 1, sizeof (*ret->{child.fixname}));\n')
    c_file.append(f'        if (ret->{child.fixname} == NULL)\n')
    c_file.append('          return NULL;\n')
    c_file.append('        for (i = 0; i < len; i++)\n')
    c_file.append('          {\n')
    c_file.append('            json_object *jval;\n')
    c_file.append('            const char *tmpkey = keys[i];\n')
    c_file.append('            ret->keys[i] = strdup (tmpkey ? tmpkey : "");\n')
    c_file.append('            if (ret->keys[i] == NULL)\n')
    c_file.append("              return NULL;\n")
    c_file.append('            jval = json_object_array_get_idx(values, i);\n')
    c_file.append(f'            ret->{child.fixname}[i] = make_{childname} (jval, ctx, err);\n')
    c_file.append(f'            if (ret->{child.fixname}[i] == NULL)\n')
    c_file.append("              return NULL;\n")
    c_file.append('          }\n')
    c_file.append('      }\n')


def parse_obj_type_array(obj, c_file, prefix, obj_typename):
    if obj.subtypobj or obj.subtyp == 'object':
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_name_substr(obj.name, prefix)
        c_file.append('    do\n')
        c_file.append('      {\n')
        c_file.append(f'       json_object *tmp = json_object_object_get (tree, "{obj.origname}");\n')                       
        c_file.append('        if (tmp != NULL && json_object_is_type(tmp, json_type_array))\n')
        c_file.append('          {\n')
        c_file.append('            int len = json_object_array_length (tmp);\n')
        c_file.append(f'            ret->{obj.fixname}_len = len;\n')
        c_file.append(f'            ret->{obj.fixname} = calloc (len + 1, sizeof (*ret->{obj.fixname}));\n')
        c_file.append(f'            if (ret->{obj.fixname} == NULL)\n')
        c_file.append('              return NULL;\n')
        c_file.append('             json_object *value;\n')
        c_file.append('             size_t i;\n')
        if obj.doublearray:
            c_file.append(f'            ret->{obj.fixname}_item_lens = calloc ( len + 1, sizeof (size_t));\n')
            c_file.append(f'            if (ret->{obj.fixname}_item_lens == NULL)\n')
            c_file.append('                return NULL;\n')
        c_file.append('            for(int i = 0; i < len ; i++)\n')
        c_file.append('              {\n')
        c_file.append('                 json_object *value = json_object_array_get_idx(tmp, i);\n')
        if obj.doublearray:
            c_file.append('                size_t rec_len = json_object_array_length(value);\n')
            c_file.append(f'                ret->{obj.fixname}[i] = calloc ( rec_len + 1, sizeof (**ret->{obj.fixname}));\n')
            c_file.append(f'                if (ret->{obj.fixname}[i] == NULL)\n')
            c_file.append('                    return NULL;\n')
            c_file.append('                for(size_t j = 0; j < rec_len ; j++)\n')
            c_file.append('                  {\n')
            c_file.append('                     json_object *rec_value = json_object_array_get_idx(value, j);\n')
            c_file.append(f'                    ret->{obj.fixname}[i][j] = make_{typename} (rec_value, ctx, err);\n')
            c_file.append(f'                    if (ret->{obj.fixname}[i][j] == NULL)\n')
            c_file.append("                        return NULL;\n")
            c_file.append(f'                    ret->{obj.fixname}_item_lens[i] += 1;\n')
            c_file.append('                  };\n')
        else:
            c_file.append(f'                ret->{obj.fixname}[i] = make_{typename} (value, ctx, err);\n')
            c_file.append(f'                if (ret->{obj.fixname}[i] == NULL)\n')
            c_file.append("                  return NULL;\n")
        c_file.append('              }\n')
        c_file.append('          }\n')
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    else:
        c_file.append('    do\n')
        c_file.append('      {\n')
        c_file.append(f'       json_object *tmp = json_object_object_get (tree, "{obj.origname}");\n')
        c_file.append('        if (tmp != NULL &&  !json_object_is_type(tmp, json_type_null))\n')
        c_file.append('          {\n')
        c_file.append('            int len = json_object_array_length(tmp);\n')
        c_file.append(f'            ret->{obj.fixname}_len = len;\n')
        c_file.append(f'            ret->{obj.fixname} = calloc (len + 1, sizeof (*ret->{obj.fixname}));\n')
        c_file.append(f'            if (ret->{obj.fixname} == NULL)\n')
        c_file.append('              return NULL;\n')
        if obj.doublearray:
            c_file.append(f'            ret->{obj.fixname}_item_lens = calloc ( len + 1, sizeof (size_t));\n')
            c_file.append(f'            if (ret->{obj.fixname}_item_lens == NULL)\n')
            c_file.append('                return NULL;\n')
        c_file.append('            for(int i = 0; i < len; i++)\n')
        c_file.append('              {\n')
        c_file.append('                 json_object *value = json_object_array_get_idx(tmp, i);\n')
        if obj.doublearray:
            c_file.append('                     int rec_len = json_object_array_length(value);\n')
            c_file.append(f'                    ret->{obj.fixname}[i] = calloc ( json_object_array_length(value) + 1, sizeof (**ret->{obj.fixname}));\n')
            c_file.append(f'                    if (ret->{obj.fixname}[i] == NULL)\n')
            c_file.append('                        return NULL;\n')
            c_file.append('                    for(int j = 0; j < rec_len; i++)\n')
            c_file.append('                      {\n')
            c_file.append('                         json_object *rec_value = json_object_array_get_idx(value, j);\n\n')
            read_val_generator(c_file, 5, 'rec_value', \
                                f"ret->{obj.fixname}[i][j]", obj.subtyp, obj.origname, obj_typename)
            c_file.append(f'                        ret->{obj.fixname}_item_lens[i] += 1;\n')
            c_file.append('                    };\n')
        else:
            read_val_generator(c_file, 4, 'value', \
                                f"ret->{obj.fixname}[i]", obj.subtyp, obj.origname, obj_typename)
        c_file.append('              }\n')
        c_file.append('        }\n')
        c_file.append('      }\n')
        c_file.append('    while (0);\n')

def parse_obj_type(obj, c_file, prefix, obj_typename):
    """
    Description: generate c language for parse object type
    Interface: None
    History: 2019-06-17
    """
    if obj.typ == 'string':
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'json_object_object_get (tree, "{obj.origname}")', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    elif helpers.judge_data_type(obj.typ):
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'json_object_object_get (tree, "{obj.origname}")', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    elif helpers.judge_data_pointer_type(obj.typ):
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'json_object_object_get (tree, "{obj.origname}")', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    if obj.typ == 'boolean':
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'json_object_object_get (tree, "{obj.origname}")', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    if obj.typ == 'booleanPointer':
        c_file.append('    do\n')
        c_file.append('      {\n')
        read_val_generator(c_file, 2, f'json_object_object_get (tree, "{obj.origname}")', \
                             f"ret->{obj.fixname}", obj.typ, obj.origname, obj_typename)
        c_file.append('      }\n')
        c_file.append('    while (0);\n')
    elif obj.typ == 'object' or obj.typ == 'mapStringObject':
        if obj.subtypname is not None:
            typename = obj.subtypname
        else:
            typename = helpers.get_prefixed_name(obj.name, prefix)
        c_file.append(
            f'    ret->{obj.fixname} = make_{typename} (json_object_object_get (tree, "{obj.origname}"), ctx, err);\n')
        c_file.append(f"    if (ret->{obj.fixname} == NULL && *err != 0)\n")
        c_file.append("      return NULL;\n")
    elif obj.typ == 'array':
        parse_obj_type_array(obj, c_file, prefix, obj_typename)
    elif helpers.valid_basic_map_name(obj.typ):
        c_file.append('    do\n')
        c_file.append('      {\n')
        c_file.append(f'        json_object *tmp = json_object_object_get (tree, "{obj.origname}");\n')
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
        
        condition = ", ".join([f'"{i.origname}"' for i in obj.children])
        c_file.append("""
    if (json_object_is_type(tree, json_type_object))
      {
        if (ctx->options & OPT_PARSE_FULLKEY)
          {
            if (tree == NULL)
                return NULL;
          }
        """
        f"int len = {len(obj.children)};\n"
        f"const char *excluded[] = {'{'}{condition}{'}'};"
        """
        json_object *resi = copy_unmatched_fields(tree, excluded, len);

        int resilen = json_object_object_length(resi);

        if (ctx->options & OPT_PARSE_FULLKEY && resi != NULL && resilen > 0)
          ret->_residual = resi;
      }
""")


def parse_json_objecto_c(obj, c_file, prefix):
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
    c_file.append(f"define_cleaner_function ({typename} *, free_{typename})\n")
    c_file.append(f"{typename} *\nmake_{typename} (json_object *tree, const struct parser_context *ctx, parser_error *err)\n")
    c_file.append("{\n")
    c_file.append(f"    __auto_cleanup(free_{typename}) {typename} *ret = NULL;\n")
    c_file.append("    *err = NULL;\n")
    c_file.append("    (void) ctx;  /* Silence compiler warning.  */\n")
    c_file.append("    if (tree == NULL)\n")
    c_file.append("      return NULL;\n")
    c_file.append("    if (json_object_is_type(tree, json_type_null))\n")
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
    c_file.append('    size_t len = 0, i;\n')
    c_file.append("    if (ptr != NULL)\n")
    c_file.append("        len = ptr->len;\n")
    c_file.append(f'    if (len || (ptr != NULL && ptr->keys != NULL && ptr->{child.fixname} != NULL))\n')
    c_file.append('      {\n')
    c_file.append('        for (i = 0; i < len; i++)\n')
    c_file.append('          {\n')
    c_file.append('             json_object *subroot = json_object_new_object();\n')
    c_file.append(f'            stat = gen_{childname} (subroot, ptr->{child.fixname}[i], err);\n')
    c_file.append("            if (stat != JSON_GEN_SUCCESS)\n")
    c_file.append("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    c_file.append('            char *str = ptr->keys[i] ? ptr->keys[i] : "";\n')
    c_file.append('            stat = json_object_object_add (root, (const char *)str, subroot);\n')
    c_file.append("            if (stat != JSON_GEN_SUCCESS)\n")
    c_file.append("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    c_file.append('          }\n')
    c_file.append('      }\n')

def get_obj_arr_obj_array(obj, c_file, prefix):
    if obj.subtypobj or obj.subtyp == 'object':
        l = len(obj.origname)
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_name_substr(obj.name, prefix)
        c_file.append(f'    if (ptr != NULL && ptr->{obj.fixname} != NULL)\n')
        c_file.append('      {\n')
        c_file.append('        size_t len = 0, i;\n')
        c_file.append(f"        if (ptr != NULL && ptr->{obj.fixname} != NULL)\n")
        c_file.append(f"            len = ptr->{obj.fixname}_len;//{obj.subtypobj}\n")
        c_file.append(f'        json_object *subroot = json_object_new_array();\n')
        c_file.append('        for (i = 0; i < len; i++)\n')
        c_file.append('          {\n')
        if obj.doublearray:
            c_file.append('            json_object *subsubroot = json_object_new_array();\n')
            c_file.append("            size_t j;\n")
            c_file.append(f'            for (j = 0; j < ptr->{obj.fixname}_item_lens[i]; j++)\n')
            c_file.append('              {\n')
            c_file.append('                 json_object *subobj = json_object_new_object();\n')
            c_file.append(f'                stat = gen_{typename} (subobj, ptr->{obj.fixname}[i][j], err);\n')
            c_file.append("                if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                    GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append("                stat = json_object_array_add (subsubroot, subobj);\n")
            c_file.append("                if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                     GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append('              }\n')
            c_file.append('            stat = json_object_array_add (subroot, subsubroot);\n')
        else:
            c_file.append(f'            json_object *obj = json_object_new_object();\n')
            c_file.append(f'            stat = gen_{typename} (obj, ptr->{obj.fixname}[i], err);\n')
            c_file.append("            if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append("            stat = json_object_array_add (subroot, obj);\n")
            c_file.append("            if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append('          }\n')
        c_file.append(f'         stat = json_object_object_add(root, (const char *)("{obj.origname}"), subroot);\n')
        c_file.append('      }\n')
    elif obj.subtyp == 'byte':
        l = len(obj.origname)
        c_file.append(f'    if (ptr != NULL && ptr->{obj.fixname} != NULL && ptr->{obj.fixname}_len)\n')
        c_file.append('      {\n')
        c_file.append('        const char *str = "";\n')
        c_file.append('        size_t len = 0;\n')
        if obj.doublearray:
            c_file.append('         json_object *subroot = json_object_new_array();\n')
            c_file.append("        {\n")
            c_file.append("            size_t i;\n")
            c_file.append(f"            for (i = 0; i < ptr->{obj.fixname}_len; i++)\n")
            c_file.append("              {\n")
            c_file.append(f"                if (ptr->{obj.fixname}[i] != NULL)\n")
            c_file.append(f"                    str = (const char *)ptr->{obj.fixname}[i];\n")
            c_file.append("                else ()\n")
            c_file.append("                    str = "";\n")
            c_file.append('                stat = json_object_array_add  (subroot, json_object_new_string((const char *)str));\n')
            c_file.append("              }\n")
            c_file.append("        }\n")
            c_file.append(f'        stat = json_object_object_add (root, (const char *)("{obj.origname}"), subroot);\n')
        else:
            c_file.append(f"        if (ptr != NULL && ptr->{obj.fixname} != NULL)\n")
            c_file.append("          {\n")
            c_file.append(f"            str = (const char *)ptr->{obj.fixname};\n")
            c_file.append(f"            len = ptr->{obj.fixname}_len;\n")
            c_file.append("          }\n")
            c_file.append(f'        stat = json_object_object_add (root, (const char *)("{obj.origname}"), json_object_new_string((const char *)str));\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append("      }\n")
    else:
        c_file.append(f'    if (ptr != NULL && ptr->{obj.fixname} != NULL)\n')
        c_file.append('      {\n')
        c_file.append('        size_t len = 0, i;\n')
        c_file.append('        json_object *subroot = json_object_new_array();\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append(f"        if (ptr != NULL && ptr->{obj.fixname} != NULL)\n")
        c_file.append(f"          len = ptr->{obj.fixname}_len;\n")
        c_file.append('        for (i = 0; i < len; i++)\n')
        c_file.append('          {\n')

        if obj.doublearray:
            typename = helpers.get_map_c_types(obj.subtyp)
            c_file.append('            json_object *subsubroot = json_object_new_array();\n')
            c_file.append("            size_t j;\n")
            c_file.append(f'            for (j = 0; j < ptr->{obj.fixname}_item_lens[i]; j++)\n')
            c_file.append('              {\n')
            json_value_generator(c_file, 4, f"ptr->{obj.fixname}[i][j]", 'subsubroot', obj.subtyp)
            c_file.append('              }\n')
            c_file.append('            stat = json_object_array_add (subroot, subsubroot);\n')
        else:
            json_value_generator(c_file, 3, f"ptr->{obj.fixname}[i]", 'subroot', obj.subtyp)
        c_file.append('          }\n')
        c_file.append(f'     stat =  json_object_object_add(root, (const char *)("{obj.origname}"), subroot);\n')
        c_file.append('   }\n')

def get_obj_arr_obj(obj, c_file, prefix):
    """
    Description: c language generate object or array object
    Interface: None
    History: 2019-06-17
    """
    if obj.typ == 'string':
        l = len(obj.origname)
        c_file.append(f'    if (ptr != NULL && ptr->{obj.fixname} != NULL)\n' )
        c_file.append('      {\n')
        c_file.append(f'        stat = json_object_object_add(root, (const char *)("{obj.origname}"), json_object_new_string(ptr->{obj.fixname}));\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append("      }\n")
    elif helpers.judge_data_type(obj.typ):
        c_file.append(f'    if (ptr != NULL && ptr->{obj.fixname}_present)\n')
        c_file.append('      {\n')
        json_conv = 'json_real'
        if obj.typ == 'double':
            numtyp = 'double'
        elif obj.typ.startswith("int") :
            numtyp = 'int64_t'
            json_conv = 'json_object_new_int64'
        else:
            numtyp = 'uint64_t'
            json_conv = 'json_object_new_uint64'
        l = len(obj.origname)
        c_file.append(f'       {numtyp} num = 0;\n')
        c_file.append(f"       if (ptr != NULL && ptr->{obj.fixname})\n")
        c_file.append(f"            num = ({numtyp})ptr->{obj.fixname};\n")
        c_file.append(f'        stat =  json_object_object_add(root, (const char *)("{obj.origname}"), {json_conv}(num));\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append("      }\n")
    elif obj.typ == 'boolean':
        c_file.append(f'    if (ptr != NULL && ptr->{obj.fixname}_present)\n')
        c_file.append('      {\n')
        c_file.append('        bool b = false;\n')
        c_file.append(f"       if (ptr != NULL && ptr->{obj.fixname})\n")
        c_file.append(f"           b = ptr->{obj.fixname};\n")
        c_file.append(f'        stat = json_object_object_add(root, (const char *)("{obj.origname}"), json_object_new_boolean(b));\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append("        \n")
        c_file.append("      }\n")
    elif obj.typ == 'object' or obj.typ == 'mapStringObject':
        l = len(obj.origname)
        if obj.subtypname:
            typename = obj.subtypname
        else:
            typename = helpers.get_prefixed_name(obj.name, prefix)
        c_file.append(f'    if (ptr != NULL && ptr->{obj.fixname} != NULL)\n')
        c_file.append("      {\n")
        c_file.append('        json_object *subroot = json_object_new_object();\n')
        c_file.append(f'       stat = gen_{typename} (subroot, ptr != NULL ? ptr->{obj.fixname} : NULL, err);\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append(f'        stat = json_object_object_add(root, (const char *)("{obj.origname}"), subroot);\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append("      }\n")
    elif obj.typ == 'array':
        get_obj_arr_obj_array(obj, c_file, prefix)
    elif helpers.valid_basic_map_name(obj.typ):
        l = len(obj.origname)
        c_file.append(f'    if (ptr != NULL && ptr->{obj.fixname} != NULL)\n')
        c_file.append('      {\n')
        c_file.append('        json_object *subroot = json_object_new_object();\n')
        c_file.append(f'       stat = gen_{helpers.make_basic_map_name(obj.typ)} (subroot, ptr ? ptr->{obj.fixname} : NULL, err);\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append(f'       stat = json_object_object_add(root, (const char *)("{obj.fixname}"), subroot);\n')
        c_file.append("        if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append("      }\n")


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
    c_file.append(
        f"int\ngen_{typename} (json_object *root, const {typename} *ptr, " \
        "parser_error *err)\n")
    c_file.append("{\n")
    c_file.append("    int stat = JSON_GEN_SUCCESS;\n")
    c_file.append("    /* Handle cases where root is not used within body of function */\n")
    c_file.append("    if (json_object_is_type(root, json_type_null))\n")
    c_file.append("         return stat;\n")
    c_file.append("    *err = NULL;\n")
    c_file.append("    (void) ptr;  /* Silence compiler warning.  */\n")
    if obj.typ == 'mapStringObject':
        get_map_string_obj(obj, c_file, prefix)
    elif obj.typ == 'object' or (obj.typ == 'array' and obj.subtypobj):
        nodes = obj.children if obj.typ == 'object' else obj.subtypobj
        for i in nodes or []:
            get_obj_arr_obj(i, c_file, prefix)
        if obj.typ == 'object':
            if obj.children is not None:
                c_file.append("    if (ptr != NULL && ptr->_residual != NULL)\n")
                c_file.append("      {\n")
                c_file.append("        stat = json_object_update_missing_generic(root, ptr->_residual);\n")
                c_file.append("        if (JSON_GEN_SUCCESS != stat)\n")
                c_file.append("            GEN_SET_ERROR_AND_RETURN (stat, err);\n")
                c_file.append("      }\n")
    c_file.append('    return JSON_GEN_SUCCESS;\n')
    c_file.append("}\n\n")


def read_val_generator(c_file, level, src, dest, typ, keyname, obj_typename):
    """
    Description: read value generateor
    Interface: None
    History: 2019-06-17
    """
    if helpers.valid_basic_map_name(typ):
        c_file.append(f"{'    ' * level}const json_object *jval = {src};\n")
        c_file.append(f"{'    ' * level}if (jval != NULL)\n")
        c_file.append(f'{"    " * level}  {{\n')
        c_file.append(f'{"    " * (level + 1)}{dest} = make_{helpers.make_basic_map_name(typ)} (jval, ctx, err);\n')
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
        c_file.append(f"{'    ' * level}const json_object *val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f"{'    ' * (level)}  {{\n")
        c_file.append(f"{'    ' * (level + 1)}const char *str = json_object_get_string (val);\n")
        c_file.append(f"{'    ' * (level + 1)}{dest} = strdup (str ? str : \"\");\n")
        c_file.append(f"{'    ' * (level + 1)}if ({dest} == NULL)\n")
        c_file.append(f"{'    ' * (level + 1)}  return NULL;\n")
        c_file.append(f'{"    " * level}  }}\n')
    elif helpers.judge_data_type(typ):
        c_file.append(f"{'    ' * level}const json_object *val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * (level)}  {{\n')
        if typ.startswith("uint") or \
                (typ.startswith("int") and typ != "integer") or typ == "double":
            c_file.append(f"{'    ' * (level + 1)}if (!json_object_is_type (val, json_type_double))\n")
            c_file.append(f'{"    " * (level + 1)}  {{\n')
            c_file.append(f"{'    ' * (level + 1)}    *err = strdup (\"invalid type\");\n")
            c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
            c_file.append(f'{"    " * (level + 1)}  }}\n')
            c_file.append(f'{"    " * (level + 1)}{dest} = json_object_get_double(val);\n')
        elif typ == "integer":
            c_file.append(f"{'    ' * (level + 1)}if (!json_object_is_type (val, json_type_int))\n")
            c_file.append(f'{"    " * (level + 1)}  {{\n')
            c_file.append(f"{'    ' * (level + 1)}    *err = strdup (\"invalid type\");\n")
            c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
            c_file.append(f'{"    " * (level + 1)}  }}\n')
            c_file.append(f'{"    " * (level + 1)}{dest} = json_object_get_int64(val);\n')
        elif typ == "UID" or typ == "GID":
            c_file.append(f"{'    ' * (level + 1)}if (!json_object_is_type (val, json_type_int))\n")
            c_file.append(f'{"    " * (level + 1)}  {{\n')
            c_file.append(f"{'    ' * (level + 1)}    *err = strdup (\"invalid type\");\n")
            c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
            c_file.append(f'{"    " * (level + 1)}  }}\n')
            c_file.append(f'{"    " * (level + 1)}{dest} = json_object_get_uint64(val);\n')
        c_file.append(f'{"    " * (level + 1)}}}\n')
        if '[' not in dest:
            c_file.append(f"{'    ' * (level + 1)}{dest}_present = 1;\n")
        # c_file.append(f'{"    " * (level)}}}\n')
    elif helpers.judge_data_pointer_type(typ):
        num_type = helpers.obtain_data_pointer_type(typ)
        if num_type == "":
            return
        c_file.append(f"{'    ' * level}const json_object *val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * (level)}  {{\n')
        c_file.append(f'{"    " * (level + 1)}{dest} = calloc (1, sizeof ({helpers.get_map_c_types(num_type)}));\n')
        c_file.append(f"{'    ' * (level + 1)}if ({dest} == NULL)\n")
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f"{'    ' * (level + 1)}int invalid;\n")
        c_file.append(f"{'    ' * (level + 1)}if (! json_is_number (val))\n")
        c_file.append(f'{"    " * (level + 1)}  {{\n')
        c_file.append(f"{'    ' * (level + 1)}    *err = strdup (\"invalid type\");\n")
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f'{"    " * (level + 1)}}}\n')
        c_file.append(f'{"    " * (level + 1)}sinvalid = json_double_to_{num_type} (json_number_value(val), {dest});\n')
        c_file.append(f"{'    ' * (level + 1)}if (invalid)\n")
        c_file.append(f'{"    " * (level + 1)}  {{\n')
        c_file.append(f'{"    " * (level + 1)}        *err = strdup ("error allocating memory");\n')
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f'{"    " * (level + 1)}}}\n')
        c_file.append(f'{"    " * (level)}}}\n')
    elif typ == 'boolean':
        c_file.append(f"{'    ' * level}json_object *val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * (level)}  {{\n')
        c_file.append(f"{'    ' * (level + 1)}{dest} = json_object_get_boolean(val);\n")
        if '[' not in dest:
            c_file.append(f"{'    ' * (level + 1)}{dest}_present = 1;\n")
            c_file.append(f'{"    " * (level)}  }}\n')
            c_file.append(f"{'    ' * level}else\n")
            c_file.append(f'{"    " * (level)}  {{\n')
            c_file.append(f"{'    ' * (level + 1)}val = {src};\n")
            c_file.append(f"{'    ' * (level + 1)}if (val != NULL)\n")
            c_file.append(f'{"    " * (level+1)}  {{\n')
            c_file.append(f"{'    ' * (level + 2)}{dest} = 0;\n")
            c_file.append(f"{'    ' * (level + 2)}{dest}_present = 1;\n")
            c_file.append(f'{"    " * (level+1)}  }}\n')
        c_file.append(f'{"    " * (level)}  }}\n')
    elif typ == 'booleanPointer':
        c_file.append(f"{'    ' * level}json_object *val = {src};\n")
        c_file.append(f"{'    ' * level}if (val != NULL)\n")
        c_file.append(f'{"    " * (level)}  {{\n')
        c_file.append(f"{'    ' * (level + 1)}{dest} = calloc (1, sizeof (bool));\n")
        c_file.append(f"{'    ' * (level + 1)}if ({dest} == NULL)\n")
        c_file.append(f"{'    ' * (level + 1)}    return NULL;\n")
        c_file.append(f"{'    ' * (level + 1)}*({dest}) = json_object_get_boolean(val);\n")
        c_file.append(f'{"    " * (level)}  }}\n')
        c_file.append(f"{'    ' * level}else\n")
        c_file.append(f'{"    " * (level)} {{\n')
        c_file.append(f'{"    " * (level + 1)}val = json_object_object_get (tree, "{keyname}");\n')
        c_file.append(f"{'    ' * (level + 1)}if (val != NULL)\n")
        c_file.append(f'{"    " * (level + 1)}  {{\n')
        c_file.append(f"{'    ' * (level + 2)}{dest} = calloc (1, sizeof (bool));\n")
        c_file.append(f"{'    ' * (level + 2)}if ({dest} == NULL)\n")
        c_file.append(f"{'    ' * (level + 2)}  return NULL;\n")
        c_file.append(f"{'    ' * (level + 2)}*({dest}) = json_object_get_boolean(val);\n")
        c_file.append(f'{"    " * (level + 1)}}}\n')
        c_file.append(f'{"    " * (level)}}}\n')


def make_clone(obj, c_file, prefix):
    """
    Description: generate a clone operation for the specified object
    Interface: None
    History: 2024-09-03
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

    c_file.append(f"{typename} *\nclone_{typename} ({typename} *src)\n")
    c_file.append("{\n")
    c_file.append("    (void) src;  /* Silence compiler warning.  */\n")
    c_file.append(f"    __auto_cleanup(free_{typename}) {typename} *ret = NULL;\n")

    c_file.append("    ret = calloc (1, sizeof (*ret));\n")
    c_file.append("    if (ret == NULL)\n")
    c_file.append("      return NULL;\n")

    nodes = obj.children if obj.typ == 'object' else obj.subtypobj
    for i in nodes or []:
        if helpers.judge_data_type(i.typ) or i.typ == 'boolean':
            c_file.append(f"    ret->{i.fixname} = src->{i.fixname};\n")
            c_file.append(f"    ret->{i.fixname}_present = src->{i.fixname}_present;\n")
        elif i.typ == 'object':
            node_name = i.subtypname or helpers.get_prefixed_name(i.name, prefix)
            c_file.append(f"    if (src->{i.fixname})\n")
            c_file.append(f"      {{\n")
            c_file.append(f"        ret->{i.fixname} = clone_{node_name} (src->{i.fixname});\n")
            c_file.append(f"        if (ret->{i.fixname} == NULL)\n")
            c_file.append(f"          return NULL;\n")
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
            c_file.append(f"    if (src->{i.fixname})\n")
            c_file.append(f"      {{\n")
            c_file.append(f"        ret->{i.fixname} = calloc (1, sizeof ({i.subtypname}));\n")
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
            c_file.append(f"            ret->{i.fixname}->values[i] = clone_{i.subtypname}_element (src->{i.fixname}->values[i]);\n")
            c_file.append(f"            if (ret->{i.fixname}->values[i] == NULL)\n")
            c_file.append(f"              return NULL;\n")
            c_file.append(f"          }}\n")
            c_file.append(f"      }}\n")
        else:
            raise Exception("Unimplemented type for clone: %s" % i.typ)

    c_file.append(f"    return move_ptr (ret);\n")
    c_file.append("}\n\n")


def json_value_generator(c_file, level, src, dst, typ):
    """
    Description: json value generateor
    Interface: None
    History: 2019-06-17
    """
    if helpers.valid_basic_map_name(typ):
        c_file.append(f'{"    " * (level)}stat = gen_{helpers.make_basic_map_name(typ)} ({dst}, {src}, err);\n')
        c_file.append(f"{'    ' * level}if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append(f"{'    ' * (level + 1)}GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    elif typ == 'string':
        c_file.append(f'{"    " * (level)}stat = json_object_array_add ({dst}, json_object_new_string({src}));\n')
        c_file.append(f"{'    ' * level}if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append(f"{'    ' * (level + 1)}GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    elif helpers.judge_data_type(typ):
        if typ == 'double':
            c_file.append(f'{"    " * (level)}stat = json_object_array_add ({dst}, json_object_new_double({src}));\n')
        elif typ.startswith("uint") or typ == 'GID' or typ == 'UID':
            c_file.append(f"{'    ' * level}stat = json_object_array_add  ({dst}, json_object_new_uint64({src}));\n")
        else:
            c_file.append(f"{'    ' * level}stat = json_object_array_add ({dst}, json_object_new_int64({src}));\n")
        c_file.append(f"{'    ' * level}if (stat != JSON_GEN_SUCCESS)\n")
        c_file.append(f"{'    ' * (level + 1)}GEN_SET_ERROR_AND_RETURN (stat, err);\n")
    elif typ == 'boolean':
        c_file.append(f'{"    " * (level)}stat = json_object_array_add ({dst}, json_object_new_boolean({src}));\n')
        c_file.append(f"{'    ' * level}if (stat != JSON_GEN_SUCCESS)\n")
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
        c_file.append(f"        free (ptr->{i.fixname});\n")
        c_file.append(f"        ptr->{i.fixname} = NULL;\n")
        c_file.append("      }\n")
    elif i.subtyp == 'string':
        c_file_str(c_file, i)
    elif not helpers.judge_complex(i.subtyp):
        c_file.append("   {\n")
        if i.doublearray:
            c_file.append("            size_t i;\n")
            c_file.append(f"            for (i = 0; i < ptr->{i.fixname}_len; i++)\n")
            c_file.append("              {\n")
            c_file.append(f"                free (ptr->{i.fixname}[i]);\n")
            c_file.append(f"                ptr->{i.fixname}[i] = NULL;\n")
            c_file.append("              }\n")
            c_file.append(f"            free (ptr->{i.fixname}_item_lens);\n")
            c_file.append(f"            ptr->{i.fixname}_item_lens = NULL;\n")
        c_file.append(f"        free (ptr->{i.fixname});\n")
        c_file.append(f"        ptr->{i.fixname} = NULL;\n")
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
            c_file.append(f"        free (ptr->{i.fixname}[i]);\n")
            c_file.append(f"        ptr->{i.fixname}[i] = NULL;\n")
        else:
            c_file.append(f"          if (ptr->{i.fixname}[i] != NULL)\n")
            c_file.append("            {\n")
            c_file.append(f"              free_{free_func} (ptr->{i.fixname}[i]);\n")
            c_file.append(f"              ptr->{i.fixname}[i] = NULL;\n")
            c_file.append("            }\n")
        c_file.append("          }\n")
        if i.doublearray:
            c_file.append(f"        free (ptr->{i.fixname}_item_lens);\n")
            c_file.append(f"        ptr->{i.fixname}_item_lens = NULL;\n")

        c_file.append(f"        free (ptr->{i.fixname});\n")
        c_file.append(f"        ptr->{i.fixname} = NULL;\n")
        c_file.append("      }\n")
    c_typ = helpers.obtain_pointer(i.name, i.subtypobj, prefix)
    if c_typ == "":
        return True
    if i.subobj is not None:
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
            c_file.append("    json_object_put (ptr->_residual);\n")
            c_file.append("    ptr->_residual = NULL;\n")
    c_file.append("    free (ptr);\n")
    c_file.append("}\n\n")


def c_file_map_str(c_file, child, childname):
    """
    Description: generate c code for map string
    Interface: None
    History: 2019-10-31
    """
    c_file.append(f"    if (ptr->keys != NULL && ptr->{child.fixname} != NULL)\n")
    c_file.append("      {\n")
    c_file.append("        size_t i;\n")
    c_file.append("        for (i = 0; i < ptr->len; i++)\n")
    c_file.append("          {\n")
    c_file.append("            free (ptr->keys[i]);\n")
    c_file.append("            ptr->keys[i] = NULL;\n")
    c_file.append(f"            free_{childname} (ptr->{child.fixname}[i]);\n")
    c_file.append(f"            ptr->{child.fixname}[i] = NULL;\n")
    c_file.append("          }\n")
    c_file.append("        free (ptr->keys);\n")
    c_file.append("        ptr->keys = NULL;\n")
    c_file.append(f"        free (ptr->{child.fixname});\n")
    c_file.append(f"        ptr->{child.fixname} = NULL;\n")
    c_file.append("      }\n")

def c_file_str(c_file, i):
    """
    Description: generate c code template
    Interface: None
    History: 2019-10-31
    """
    c_file.append(f"    if (ptr->{i.fixname} != NULL)\n")
    c_file.append("      {\n")
    c_file.append("        size_t i;\n")
    c_file.append(f"        for (i = 0; i < ptr->{i.fixname}_len; i++)\n")
    c_file.append("          {\n")
    if i.doublearray:
        c_file.append("            size_t j;\n")
        c_file.append(f"            for (j = 0; j < ptr->{i.fixname}_item_lens[i]; j++)\n")
        c_file.append("              {\n")
        c_file.append(f"                free (ptr->{i.fixname}[i][j]);\n")
        c_file.append(f"                ptr->{i.fixname}[i][j] = NULL;\n")
        c_file.append("            }\n")
    c_file.append(f"            if (ptr->{i.fixname}[i] != NULL)\n")
    c_file.append("              {\n")
    c_file.append(f"                free (ptr->{i.fixname}[i]);\n")
    c_file.append(f"                ptr->{i.fixname}[i] = NULL;\n")
    c_file.append("              }\n")
    c_file.append("          }\n")
    if i.doublearray:
        c_file.append(f"        free (ptr->{i.fixname}_item_lens);\n")
        c_file.append(f"        ptr->{i.fixname}_item_lens = NULL;\n")
    c_file.append(f"        free (ptr->{i.fixname});\n")
    c_file.append(f"        ptr->{i.fixname} = NULL;\n")
    c_file.append("    }\n")


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
                    f"*make_{typename} (json_object *tree, const struct parser_context *ctx, parser_error *err)\n" +
                    "{\n" +
                    f"    __auto_cleanup(free_{typename}) {typename} *ptr = NULL;\n" +
                    f"    size_t alen;\n" +
                    f" "+
                    f"    (void) ctx;\n" +
                    f" "+
                    f"    if (tree == NULL || err == NULL || !json_object_is_type (tree, json_type_array))\n" +
                    f"      return NULL;\n" +
                    f"    *err = NULL;\n" +
                    f"    alen = json_object_array_length (tree);\n" +
                    f"    if (alen == 0)\n" +
                    f"      return NULL;\n" +
                    f"    ptr = calloc (1, sizeof ({typename}));\n" +
                    f"    if (ptr == NULL)\n" +
                    f"      return NULL;\n" +
                    f"    ptr->items = calloc (alen + 1, sizeof(*ptr->items));\n" +
                    f"    if (ptr->items == NULL)\n" +
                    f"      return NULL;\n" +
                    f"    ptr->len = alen;\n"
                    f"    json_object *work;"
    )

    if obj.doublearray:
        c_file.append('    ptr->subitem_lens = calloc ( alen + 1, sizeof (size_t));\n')
        c_file.append('    if (ptr->subitem_lens == NULL)\n')
        c_file.append('      return NULL;')

    c_file.append("""\n
    for(size_t i = 0; i < alen; i++)
      {
            json_object *work = json_object_array_get_idx(tree, i);
""")

    if obj.subtypobj or obj.subtyp == 'object':
        if obj.subtypname:
            subtypename = obj.subtypname
        else:
            subtypename = helpers.get_name_substr(obj.name, prefix)

        if obj.doublearray:
            c_file.append('        size_t j;\n')
            c_file.append('        size_t sublen = json_object_array_length(work);\n')
            c_file.append('        ptr->items[i] = calloc ( sublen + 1, sizeof (**ptr->items));\n')
            c_file.append('        if (ptr->items[i] == NULL)\n')
            c_file.append('          return NULL;\n')
            c_file.append('        for(size_t j = 0; j < sublen; j++)\n')
            c_file.append('          {\n')
            c_file.append('              json_object *nested_item = json_object_array_get_idx(work, j);\n')
            c_file.append(f'              ptr->items[i][j] = make_{subtypename} (nested_item, ctx, err);\n')
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
            c_file.append('        const char *str = json_object_get_string (work);\n')
            c_file.append('        ptr->items[j] = (uint8_t *)strdup (str ? str : "");\n')
            c_file.append('        if (ptr->items[j] == NULL)\n')
            c_file.append("          return NULL;\n")
        else:
            c_file.append('        const char *str = json_object_get_string (tree);\n')
            c_file.append('        memcpy(ptr->items, str ? str : "", strlen(str ? str : ""));\n')
            c_file.append('        break;\n')
    else:
        if obj.doublearray:
            c_file.append('        size_t sublen = json_object_array_length(work);\n')
            c_file.append('        ptr->items[i] = calloc ( json_object_array_length(work) + 1, sizeof (**ptr->items));\n')
            c_file.append('        if (ptr->items[i] == NULL)\n')
            c_file.append('          return NULL;\n')
            c_file.append('        for(size_t j = 0; j < sublen; j++)\n')
            c_file.append('          {\n')
            c_file.append('             json_object *nested_item = json_object_array_get_idx(work, j);\n')
            read_val_generator(c_file, 3, 'nested_item', \
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
    elif not helpers.judge_complex(obj.subtyp):
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

    c_file.append(f"int gen_{typename} (json_object *root, const {typename} *ptr, " + """
                       parser_error *err)
{
    size_t i;
    int stat;
    if (ptr == NULL)
        return JSON_GEN_SUCCESS;
""")

    if obj.subtypobj or obj.subtyp == 'object':
        c_file.append("""\n
    for (i = 0; i < ptr->len; i++)
""")

        if obj.subtypname:
            subtypename = obj.subtypname
        else:
            subtypename = helpers.get_name_substr(obj.name, prefix)
        c_file.append('      {\n')
        if obj.doublearray:
            c_file.append("            json_object *subroot = json_object_new_array();\n")
            c_file.append("            size_t j;\n")
            c_file.append('            for (j = 0; j < ptr->subitem_lens[i]; j++)\n')
            c_file.append('              {\n')
            c_file.append('                json_object *subobj = json_object_new_object();\n')
            c_file.append(f'               stat = gen_{subtypename} (subobj, ptr->items[i][j], err);\n')
            c_file.append("                if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                    GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append("                stat = json_object_array_add (subroot, subobj);\n")
            c_file.append("                if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                    GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append('              }\n')
            c_file.append("            int stat = json_object_array_add (root, subroot);\n")
            c_file.append("            if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        else:
            c_file.append("            json_object *obj = json_object_new_object();\n")
            c_file.append(f'           stat = gen_{subtypename} (obj, ptr->items[i], err);\n')
            c_file.append("            if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append("            stat = json_object_array_add (root, obj);\n\n")
            c_file.append("            if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append("""\n
            }
""")
    elif obj.subtyp == 'byte':
        c_file.append('    {\n')
        c_file.append('            const char *str = NULL;\n')
        if obj.doublearray:
            c_file.append("            {\n")
            c_file.append("                size_t i;\n")
            c_file.append("                json_object *subroot = json_object_new_array();\n")
            c_file.append("                for (i = 0; i < ptr->len; i++)\n")
            c_file.append("                  {\n")
            c_file.append("                    if (ptr->items[i] != NULL)\n")
            c_file.append("                        str = (const char *)ptr->items[i];\n")
            c_file.append("                    else ()\n")
            c_file.append("                        str = "";\n")
            c_file.append("                    json_object *jstr = json_object_new_string(str);\n")
            c_file.append("                    int stat = json_object_array_add (subroot, jstr);\n")
            c_file.append("                    if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                         GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append("                  }\n")
            c_file.append("                int stat = json_object_array_add (root, subroot);\n")
            c_file.append("                if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                     GEN_SET_ERROR_AND_RETURN (stat, err);\n")
            c_file.append("            }\n")
        else:
            c_file.append("        if (ptr != NULL && ptr->items != NULL)\n")
            c_file.append("          {\n")
            c_file.append("            str = (const char *)ptr->items;\n")
            c_file.append("          }\n")
            c_file.append("          json_object *jstr = json_object_new_string(str);\n")
            c_file.append("          int stat = json_object_array_add (root, jstr);\n")
            c_file.append("          if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("               GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        c_file.append('    }\n')
    else:
        c_file.append("""\n
    for (i = 0; i < ptr->len; i++)
      {
""")
        c_file.append('        {\n')
        if obj.doublearray:
            c_file.append("            size_t j;\n")
            c_file.append("            json_object *subroot = json_object_new_array();\n")
            c_file.append('            for (j = 0; j < ptr->subitem_lens[i]; j++)\n')
            c_file.append('              {\n')
            json_value_generator(c_file, 4, "ptr->items[i][j]", 'subroot', obj.subtyp)
            c_file.append('            }\n')
            c_file.append("            int stat = json_object_array_add (root, subroot);\n")
            c_file.append("            if (stat != JSON_GEN_SUCCESS)\n")
            c_file.append("                GEN_SET_ERROR_AND_RETURN (stat, err);\n")
        else:
            json_value_generator(c_file, 3, "ptr->items[i]", 'root', obj.subtyp)

        c_file.append("""\n
            }
      }
""")


    c_file.append("""\n
    if (stat != JSON_GEN_SUCCESS)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    return JSON_GEN_SUCCESS;
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
    f"\n\t\t\tptr = {typename}_parse_data (content, ctx, err);\n\t\t\t" +
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
define_cleaner_function (json_object *, json_object_put)
""" +
f"\n {typename} * " +
f"{typename}_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)\n {{ \n" +
    f"  {typename} *ptr = NULL;\n" +
    """\t__auto_cleanup(json_object_put) json_object *tree = NULL;
    enum json_tokener_error *error;
    struct parser_context tmp_ctx = { 0 };

    if (jsondata == NULL || err == NULL)
      return NULL;

    *err = NULL;
    if (ctx == NULL)
     ctx = (const struct parser_context *)(&tmp_ctx);

    tree = json_tokener_parse_verbose (jsondata, error);
    if (tree == NULL)
      {
        if (asprintf (err, "cannot parse the data: %s", "TODO") < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }\n""" +
    f"\tptr = make_{typename} (tree, ctx, err);\n" +
    "\treturn ptr; \n}\n"
)

    c_file.append("\n char * \n" +
f"{typename}_generate_json (const {typename} *ptr, parser_error *err)" +
"""{
""" +
f"    __auto_cleanup(json_object_put) json_object *root = json_object_new_{typ}();" +
"""

    if (ptr == NULL || err == NULL)
      return NULL;

    *err = NULL;
""" +
    f"if (JSON_GEN_FAILED == gen_{typename} (root, ptr, err))" +
    """  {
        if (*err == NULL)
            *err = strdup ("Failed to generate json");
        return NULL;
      }

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);

    return json_str;
}
""")
