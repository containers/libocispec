#!/usr/bin/env python
#
# libocispec - a C library for parsing OCI spec files.
#
# Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
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

import os, sys, json

class Name:
    def __init__(self, name, leaf=None):
        self.name = name
        self.leaf = leaf

    def __repr__(self):
        return self.name
    def __str__(self):
        return self.name
    def append(self, leaf):
        if self.name != "":
            prefix_name = self.name + '_'
        else:
            prefix_name = ""
        return Name(prefix_name + leaf, leaf)

class Node:
    def __init__(self, name, typ, children, subtyp=None, subtypobj=None, required=None):
        self.name = name.name
        self.origname = name.leaf or name.name
        self.typ = typ
        self.children = children
        self.subtyp = subtyp
        self.subtypobj = subtypobj
        self.required = required

    def __repr__(self):
        if self.subtyp is not None:
            return "name:(%s) type:(%s -> %s)" % (self.name, self.typ, self.subtyp)
        return "name:(%s) type:(%s)" % (self.name, self.typ)

c_types_mapping = {
    'string' : 'char *',
    'integer' : 'int',
    'boolean' : 'bool',
    'int8' : 'int8_t',
    "int16" : 'int16_t',
    "int32" : "int32_t",
    "int64" : "int64_t",
    'uint8' : 'uint8_t',
    "uint16" : 'uint16_t',
    "uint32" : "uint32_t",
    "uint64" : "uint64_t",
    "UID" : "uid_t",
    "GID" : "gid_t",
}

def make_name_array(name):
    return "oci_container_%s_element" % name

def make_name(name):
    return "oci_container_%s" % name

def make_pointer(name, typ):
    if typ != 'object' and typ != 'mapStringString':
        return None
    return "%s *" % make_name(name)

def is_compound_object(typ):
    return typ in ['object', 'array']

def is_numeric_type(typ):
    if typ.startswith("int") or typ.startswith("uint"):
        return True
    return typ in ["integer", "UID", "GID"]

def get_pointer(name, typ):
    ptr = make_pointer(name, typ)
    if ptr:
        return ptr
    if typ == "string":
        return "char *"
    if typ in ["mapStringString", "ArrayOfStrings"]:
        return "%s *" % typ
    return None

def append_C_code(obj, c_file):
    generate_C_parse(obj, c_file)
    generate_C_free(obj, c_file)

def generate_C_parse(obj, c_file):
    if not is_compound_object(obj.typ):
        return
    if obj.typ == 'object':
        obj_typename = typename = make_name(obj.name)
    elif obj.typ == 'array':
        obj_typename = typename = make_name_array(obj.name)
        objs = obj.subtypobj
        if objs is None:
            return
    elif obj.typ == 'mapStringString':
        obj_typename = typename = make_name(obj.name)
        objs = []


    c_file.write("%s *make_%s (yajl_val tree, struct libocispec_context *ctx, oci_parser_error *err) {\n" % (typename, typename))
    c_file.write("    %s *ret = NULL;\n" % (typename))
    c_file.write("    *err = 0;\n")
    c_file.write("    if (tree == NULL)\n")
    c_file.write("        return ret;\n")
    c_file.write("    ret = safe_malloc (sizeof (*ret));\n")
    c_file.write("    memset (ret, 0, sizeof (*ret));\n")

    if obj.typ == 'mapStringString':
        pass
    elif obj.typ == 'object' or (obj.typ == 'array' and obj.subtypobj):
        nodes = obj.children if obj.typ == 'object' else obj.subtypobj

        required_to_check = []
        for i in (nodes or []):
            if obj.required and i.origname in obj.required and not is_numeric_type(i.typ):
                required_to_check.append(i)
            if i.typ == 'string':
                c_file.write('    {\n')
                read_value_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_string)' % i.origname, "ret->%s" % i.origname, i.typ)
                c_file.write('    }\n')
            elif is_numeric_type(i.typ):
                c_file.write('    {\n')
                read_value_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_number)' % i.origname, "ret->%s" % i.origname, i.typ)
                c_file.write('    }\n')
            if i.typ == 'boolean':
                c_file.write('    {\n')
                read_value_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_true)' % i.origname, "ret->%s" % i.origname, i.typ)
                c_file.write('    }\n')
            elif i.typ == 'object':
                typename = make_name(i.name)
                c_file.write('    ret->%s = make_%s (get_val (tree, "%s", yajl_t_object), ctx, err);\n' % (i.origname, typename, i.origname))
                c_file.write("    if (ret->%s == NULL && *err != 0) {\n" % i.origname)
                c_file.write("        free_%s (ret);\n" % obj_typename)
                c_file.write("        return NULL;\n")
                c_file.write("    }\n")
            elif i.typ == 'array' and i.subtypobj:
                typename = make_name_array(i.name)
                c_file.write('    {\n')
                c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_array);\n' % (i.origname))
                c_file.write('        if (tmp != NULL) {\n')
                c_file.write('            size_t i;\n')
                c_file.write('            ret->%s_len = YAJL_GET_ARRAY (tmp)->len;\n' % (i.origname))
                c_file.write('            ret->%s = safe_malloc (YAJL_GET_ARRAY (tmp)->len * sizeof (*ret->%s));\n' % (i.origname, i.origname))
                c_file.write('            for (i = 0; i < YAJL_GET_ARRAY (tmp)->len; i++) {\n')
                c_file.write('                yajl_val tmpsub = YAJL_GET_ARRAY (tmp)->values[i];\n')
                c_file.write('                ret->%s[i] = make_%s (tmpsub, ctx, err);\n' % (i.origname, typename))
                c_file.write('            }\n')
                c_file.write('        }\n')
                c_file.write('    }\n')
            elif i.typ == 'array':
                c_file.write('    {\n')
                c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_array);\n' % (i.origname))
                c_file.write('        if (tmp != NULL) {\n')
                c_file.write('            size_t i;\n')
                c_file.write('            ret->%s_len = YAJL_GET_ARRAY (tmp)->len;\n' % (i.origname))
                c_file.write('            ret->%s = safe_malloc (YAJL_GET_ARRAY (tmp)->len * sizeof (*ret->%s));\n' % (i.origname, i.origname))
                c_file.write('            for (i = 0; i < YAJL_GET_ARRAY (tmp)->len; i++) {\n')
                c_file.write('                yajl_val tmpsub = YAJL_GET_ARRAY (tmp)->values[i];\n')
                read_value_generator(c_file, 4, 'tmpsub', "ret->%s[i]" % i.origname, i.subtyp)
                c_file.write('            }\n')
                c_file.write('        }\n')
                c_file.write('    }\n')
            elif i.typ == 'mapStringString':
                c_file.write('    {\n')
                c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_object);\n' % (i.origname))
                c_file.write('        if (tmp != NULL) {\n')
                c_file.write('            ret->%s = read_map_string_string (tmp);\n' % (i.origname))
                c_file.write('        }\n')
                c_file.write('    }\n')
        for i in required_to_check:
            c_file.write('    if (ret->%s == NULL) {\n' % i.origname)
            c_file.write('        if (asprintf (err, "Required field %%s not present", "%s") < 0) {\n' % i.origname)
            c_file.write('            *err = "error allocating memory";\n')
            c_file.write('            return NULL;\n')
            c_file.write("        }\n")
            c_file.write("        free_%s (ret);\n" % obj_typename)
            c_file.write("        return NULL;\n")
            c_file.write('    }\n')

        if obj.typ == 'object' and obj.children is not None:
            #O(n^2) complexity, but the objects should not really be big...
            condition = " &&\n                ".join(['strcmp (tree->u.object.keys[i], "%s")' % i.origname for i in obj.children])
            c_file.write("""
    if (tree->type == yajl_t_object && (ctx->options & LIBOCISPEC_OPTIONS_STRICT)) {
        int i;
        for (i = 0; i < tree->u.object.len; i++)
            if (%s) {
                fprintf (ctx->stderr, "WARNING: unknown key found: %%s\\n", tree->u.object.keys[i]);
            }
        }
""" % condition)

    c_file.write('    return ret;\n')
    c_file.write("}\n\n")

def read_value_generator(c_file, level, src, dest, typ):
    if typ == 'mapStringString':
        c_file.write('%s%s = read_map_string_string (%s);\n' % ('    ' * (level), dest, src))
    elif typ == 'string':
        c_file.write('%sif (%s)\n' % ('    ' * level, src))
        c_file.write('%s%s = strdup (YAJL_GET_STRING (%s) ? : "");\n' % ('    ' * (level + 1), dest, src))
    elif is_numeric_type(typ):
        c_file.write('%sif (%s)\n' % ('    ' * level, src))
        if typ.startswith("uint"):
            c_file.write('%s%s = strtoull (YAJL_GET_NUMBER (%s), NULL, 10);\n' % ('    ' * (level + 1), dest, src))
        else:
            c_file.write('%s%s = strtoll (YAJL_GET_NUMBER (%s), NULL, 10);\n' % ('    ' * (level + 1), dest, src))
    elif typ == 'boolean':
        c_file.write('%sif (%s)\n' % ('    ' * level, src))
        c_file.write('%s%s = YAJL_IS_TRUE (%s);\n' % ('    ' * (level + 1), dest, src))


def generate_C_free(obj, c_file):
    if not is_compound_object(obj.typ) and obj.typ != 'mapStringString':
        return

    typename = make_name(obj.name)
    if obj.typ == 'mapStringString':
        objs = []
    if obj.typ == 'object':
        objs = obj.children
    elif obj.typ == 'array':
        objs = obj.subtypobj
        if objs is None:
            return
        typename = typename + "_element"

    c_file.write("void free_%s (%s *ptr) {\n" % (typename, typename))
    if obj.typ == 'mapStringString':
        c_file.write("    free_cells (ptr);\n")
        c_file.write("    ptr = NULL;\n")

    for i in (objs or []):
        if i.typ == 'mapStringString':
            free_func = make_name(i.name)
            c_file.write("    free_%s (ptr->%s);\n" % (free_func, i.origname))
            c_file.write("    ptr->%s = NULL;\n" % (i.origname))
        elif i.typ == 'array':
            if i.subtyp == 'mapStringString':
                free_func = make_name_array(i.name)
                c_file.write("    if (ptr->%s) {\n" % i.origname)
                c_file.write("        size_t i;\n")
                c_file.write("        for (i = 0; i < ptr->%s_len; i++) {\n" % i.origname)
                c_file.write("            free_cells (ptr->%s[i]);\n" % (i.origname))
                c_file.write("        }\n")
                c_file.write("        ptr->%s = NULL;\n" % (i.origname))
                c_file.write("    }\n")
            elif i.subtyp == 'string':
                free_func = make_name_array(i.name)
                c_file.write("    if (ptr->%s) {\n" % i.origname)
                c_file.write("        size_t i;\n")
                c_file.write("        for (i = 0; i < ptr->%s_len; i++) {\n" % i.origname)
                c_file.write("            free (ptr->%s[i]);\n" % (i.origname))
                c_file.write("        }\n")
                c_file.write("        ptr->%s = NULL;\n" % (i.origname))
                c_file.write("    }\n")
            elif i.subtypobj is not None:
                free_func = make_name_array(i.name)
                c_file.write("    if (ptr->%s) {\n" % i.origname)
                c_file.write("        size_t i;\n")
                c_file.write("        for (i = 0; i < ptr->%s_len; i++)\n" % i.origname)
                c_file.write("            free_%s (ptr->%s[i]);\n" % (free_func, i.origname))
                c_file.write("        free (ptr->%s);\n" % i.origname)
                c_file.write("        ptr->%s = NULL;\n" % (i.origname))
                c_file.write("    }\n")

            c_typ = get_pointer(i.name, i.subtypobj)
            if c_typ == None:
                continue
            if i.subobj is not None:
                c_typ = c_typ + "_element"
            c_file.write("    free_%s (ptr->%s);\n" % (c_typ, i.origname))
            c_file.write("    ptr->%s = NULL;\n" % (i.origname))
        else: # not array
            typename = make_name(i.name)
            if i.typ == 'string':
                c_file.write("    free (ptr->%s);\n" % (i.origname))
                c_file.write("    ptr->%s = NULL;\n" % (i.origname))
            elif i.typ == 'object':
                c_file.write("    if (ptr->%s)\n" % (i.origname))
                c_file.write("        free_%s (ptr->%s);\n" % (typename, i.origname))
                c_file.write("    ptr->%s = NULL;\n" % (i.origname))
    c_file.write("}\n\n")

def append_type_C_header(obj, header):
    if obj.typ == 'mapStringString':
        typename = make_name(obj.name)
        header.write("typedef string_cells %s;\n\n" % typename)
    elif obj.typ == 'array':
        if not obj.subtypobj:
            return
        header.write("typedef struct {\n")
        for i in obj.subtypobj:
            if i.typ == 'array':
                c_typ = make_pointer(i.name, i.subtyp) or c_types_mapping[i.subtyp]
                if i.subtypobj is not None:
                    c_typ = make_name_array(i.name)

                if not is_compound_object(i.subtyp):
                    header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.origname))
                else:
                    header.write("    %s **%s;\n" % (c_typ, i.origname))
                header.write("    size_t %s;\n\n" % (i.origname + "_len"))
            else:
                c_typ = make_pointer(i.name, i.typ) or c_types_mapping[i.typ]
                header.write("    %s%s%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.origname))
        typename = make_name_array(obj.name)
        header.write("}\n%s;\n\n" % typename)
        header.write("void free_%s (%s *ptr);\n\n" % (typename, typename))
        header.write("%s *make_%s (yajl_val tree, struct libocispec_context *ctx, oci_parser_error *err);\n\n" % (typename, typename))
    elif obj.typ == 'object':
        header.write("typedef struct {\n")
        for i in (obj.children or []):
            if i.typ == 'array':
                if i.subtypobj is not None:
                    c_typ = make_name_array(i.name)
                else:
                    c_typ = make_pointer(i.name, i.subtyp) or c_types_mapping[i.subtyp]

                if i.subtyp == 'mapStringString':
                    header.write("    %s **%s;\n" % (make_name_array(i.name), i.origname))
                elif not is_compound_object(i.subtyp):
                    header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.origname))
                else:
                    header.write("    %s%s**%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.origname))
                header.write("    size_t %s;\n\n" % (i.origname + "_len"))
            else:
                c_typ = make_pointer(i.name, i.typ) or c_types_mapping[i.typ]
                header.write("    %s%s%s;\n\n" % (c_typ, " " if '*' not in c_typ else "", i.origname))

        typename = make_name(obj.name)
        header.write("}\n%s;\n\n" % typename)
        header.write("void free_%s (%s *ptr);\n\n" % (typename, typename))
        header.write("%s *make_%s (yajl_val tree, struct libocispec_context *ctx, oci_parser_error *err);\n\n" % (typename, typename))

def get_ref(src, ref):
    f, r = ref.split("#/")
    if f == "":
        cur = src
    else:
        with open(f) as i:
            cur = src = json.loads(i.read())

    for j in r.split('/'):
        basic_types = [
            "int8", "int16", "int32", "int64",
            "uint8", "uint16", "uint32", "uint64", "UID", "GID",
            "mapStringString", "ArrayOfStrings"
        ]
        if j in basic_types:
            return src, {"type" : j}
        cur = cur[j]

    if 'type' not in cur and '$ref' in cur:
        return get_ref(src, cur['$ref'])

    return src, cur

def merge(children):
    subchildren = []
    for i in children:
        for j in i.children:
            subchildren.append(j)
    return subchildren

def resolve_type(name, src, cur):
    if '$ref' in cur:
        src, cur = get_ref(src, cur['$ref'])

    if 'patternProperties' in cur:
        # if a patternProperties, take the first value
        typ = cur['patternProperties'].values()[0]["type"]
    elif "type" in cur:
        typ = cur["type"]
    else:
        typ = "object"

    children = None
    subtyp = None
    subtypobj = None
    required = None
    if typ == 'mapStringString':
        pass
    elif typ == 'array':
        if 'allOf' in cur["items"]:
            children = merge(scan_list(name, src, cur["items"]['allOf']))
            subtyp = children[0].typ
            subtypobj = children
        elif 'anyOf' in cur["items"]:
            children = scan_list(name, src, cur["items"]['anyOf'])
            subtyp = children[0].typ
            subtypobj = children
        elif '$ref' in cur["items"]:
            item_type, src = resolve_type(name, src, cur["items"])
            return Node(name, typ, None, subtyp=item_type.typ, subtypobj=item_type.children), src
        elif 'type' in cur["items"]:
            item_type, src = resolve_type(name, src, cur["items"])
            return Node(name, typ, None, subtyp=item_type.typ, subtypobj=item_type.children), src
    elif typ == 'object':
        if 'allOf' in cur:
            children = merge(scan_list(name, src, cur['allOf']))
        elif 'anyOf' in cur:
            children = scan_list(name, src, cur['anyOf'])
        else:
            children = scan_properties(name, src, cur) if 'properties' in cur else None
        if 'required' in cur:
            required = cur['required']
    elif typ == 'ArrayOfStrings':
        typ = 'array'
        subtyp = 'string'
        children = subtypobj = None
    else:
        children = None

    return Node(name, typ, children, subtyp=subtyp, subtypobj=subtypobj, required=required), src

def scan_list(name, schema, objs):
    obj = []
    for i in objs:
        generated_name = Name(i['$ref'].split("/")[-1]) if '$ref' in i else name
        node, _ = resolve_type(generated_name, schema, i)
        if node:
            obj.append(node)
    return obj

def scan_dict(name, schema, objs):
    obj = []
    for i in objs:
        node, _ = resolve_type(name.append(i), schema, objs[i])
        if node:
            obj.append(node)

    return obj

def scan_properties(name, schema, props):
    return scan_dict(name, schema, props['properties'])

def scan_main(schema):
    return Node(Name("container"), "object", scan_properties(Name(""), schema, schema))

def flatten(tree, structs, visited={}):
    if tree.children is not None:
        for i in tree.children:
            flatten(i, structs, visited=visited)
    if tree.subtypobj is not None:
        for i in tree.subtypobj:
            flatten(i, structs, visited=visited)

    if tree.typ == 'array' and tree.subtyp == 'mapStringString':
        name = Name(tree.name + "_element")
        node = Node(name, tree.subtyp, None)
        flatten(node, structs, visited)

    id_ = "%s:%s" % (tree.name, tree.typ)
    if id_ not in visited.keys():
        structs.append(tree)
        visited[id_] = tree

    return structs

def generate_C_header(structs, header):
    header.write("/* autogenerated file */\n")
    header.write("#ifndef SCHEMA_H\n")
    header.write("# define SCHEMA_H\n\n")
    header.write("# include <stdio.h>\n")
    header.write("# include <sys/types.h>\n")
    header.write("# include <stdbool.h>\n")
    header.write("# include <yajl/yajl_tree.h>\n")
    header.write("# include <stdint.h>\n\n")
    header.write("# undef linux\n\n")
    header.write("# define LIBOCISPEC_OPTIONS_STRICT 1\n")
    header.write("typedef char * oci_parser_error;\n")
    header.write("typedef struct {\n    char **keys;\n    char **values;\n    size_t len;\n} string_cells;\n\n")
    header.write("struct libocispec_context {\n    int options;\n    FILE *stderr;\n};\n\n")
    for i in structs:
        append_type_C_header(i, header_file)
    header.write("oci_container_container *oci_parse_file (const char *filename, struct libocispec_context *ctx, oci_parser_error *err);\n\n")
    header.write("#endif\n")

def generate_C_code(structs, header_name, c_file):
    c_file.write("// autogenerated file\n")
    c_file.write("# ifndef _GNU_SOURCE\n")
    c_file.write("#  define _GNU_SOURCE\n")
    c_file.write("# endif\n")
    c_file.write('#include <stdlib.h>\n')
    c_file.write('#include <string.h>\n')
    c_file.write('#include <stdio.h>\n')
    c_file.write('#include "read-file.h"\n')
    c_file.write('#include "%s"\n\n' % header_name)
    c_file.write("FILE *oci_parser_errfile;\n\n")
    c_file.write('yajl_val get_val(yajl_val tree, const char *name, yajl_type type) {\n')
    c_file.write('    const char *path[] = { name, NULL };\n')
    c_file.write('    return yajl_tree_get (tree, path, type);\n')
    c_file.write('}\n\n')
    c_file.write('void free_cells (string_cells *cells) {\n')
    c_file.write("    if (cells) {\n")
    c_file.write("        size_t i;\n")
    c_file.write("        for (i = 0; i < cells->len; i++) {\n")
    c_file.write("            free (cells->keys[i]);\n")
    c_file.write("            free (cells->values[i]);\n")
    c_file.write("        }\n")
    c_file.write("        free (cells);\n")
    c_file.write("    }\n")
    c_file.write("}\n\n")
    c_file.write('void *safe_malloc (size_t size) {\n')
    c_file.write("    void *ret = malloc (size);\n")
    c_file.write("    if (ret == NULL)\n")
    c_file.write("        abort ();\n")
    c_file.write("    return ret;\n")
    c_file.write("}\n\n")

    c_file.write('string_cells *read_map_string_string (yajl_val src) {\n')
    c_file.write('    string_cells *ret = NULL;\n')
    c_file.write('    if (src != NULL) {\n')
    c_file.write('        size_t i;\n')
    c_file.write('        ret = safe_malloc (sizeof (string_cells));\n')
    c_file.write('        ret->len = YAJL_GET_OBJECT (src)->len;\n')
    c_file.write('        ret->keys = safe_malloc (YAJL_GET_OBJECT (src)->len * sizeof (char *));\n')
    c_file.write('        ret->values = safe_malloc (YAJL_GET_OBJECT (src)->len * sizeof (char *));\n')
    c_file.write('        for (i = 0; i < YAJL_GET_OBJECT (src)->len; i++) {\n')
    c_file.write('            yajl_val srcsub = YAJL_GET_OBJECT (src)->values[i];\n')
    c_file.write('            ret->keys[i] = strdup (YAJL_GET_OBJECT (src)->keys[i] ? : "");\n')
    c_file.write('            if (srcsub)\n')
    c_file.write('                ret->values[i] = strdup (YAJL_GET_STRING (srcsub) ? : "");\n')
    c_file.write('            else\n')
    c_file.write('                ret->values[i] = NULL;\n')
    c_file.write('        }\n')
    c_file.write('    }\n')
    c_file.write('    return ret;\n')
    c_file.write('}\n\n')

    for i in structs:
        append_C_code(i, c_file)

def generate_C_epilogue(c_file):
    c_file.write("""\n
oci_container_container *oci_parse_file (const char *filename, struct libocispec_context *ctx, oci_parser_error *err) {
    yajl_val tree;
    size_t filesize;
    *err = NULL;
    struct libocispec_context tmp_ctx;
    if (!ctx) {
       ctx = &tmp_ctx;
       memset (&tmp_ctx, 0, sizeof (tmp_ctx));
    }
    char *content = read_file (filename, &filesize);
    char errbuf[1024];
    if (content == NULL) {
        *err = strdup ("cannot read the file");
        return NULL;
    }
    tree = yajl_tree_parse (content, errbuf, sizeof(errbuf));
    free (content);
    if (tree == NULL) {
        *err = strdup ("cannot parse the file");
        return NULL;
    }

    oci_container_container *container = make_oci_container_container (tree, ctx, err);
    yajl_tree_free (tree);
    return container;
}
""")

def generate(schema_json, header_name, header_file, c_file):
    tree = scan_main(schema_json)
    # we could do this in scan_main, but let's work on tree that is easier
    # to access.
    structs = flatten(tree, [])
    generate_C_header(structs, header_file)
    generate_C_code(structs, header_name, c_file)
    generate_C_epilogue(c_file)

if __name__ == "__main__":
    schema_file = sys.argv[1]
    header = sys.argv[2]
    c_source = sys.argv[3]
    oldcwd = os.getcwd()
    with open(header + ".tmp", "w") as header_file, open(c_source + ".tmp", "w") as c_file:
        os.chdir(os.path.dirname(schema_file))
        with open(os.path.basename(schema_file)) as schema:
            schema_json = json.loads(schema.read())
        generate(schema_json, header, header_file, c_file)
    os.chdir(oldcwd)
    os.rename(header + ".tmp", header)
    os.rename(c_source + ".tmp", c_source)
