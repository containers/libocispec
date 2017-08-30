#!/usr/bin/python -Es
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

'''
This function transform "name" to "fixedname" which is conform to Linux Kernel Naming specification
It has three steps, assume that we have name = "user_CPUCached"
1. split "name" to an array by '_' and word that beginning with uppercase letter: ["user", "_", "C", "P", "U", "Cached"]
2. binding single upper string "C" "P" and "U" to "CPU", we got new array: ["user", "_", "CPU", "Cached"]
3. generate "fixedname" with above array one by one, all elements in the array are translated to lowercase,
   and add '_' between adjacent elements only when fixedname[-1] != '_' and the following element not beginning with '_'
Finally, fixedname = "user_cpu_cached"
'''
def transform_to_C_name(name):
    fixedname = ""
    subname = []
    tmpindex = 0
    length = len(name)
    i = 0
    while i < length:
        if (name[i].isupper() or name[i] == '_'):
            # split index found
            if tmpindex != i:
                subname.append(name[tmpindex:i])
                tmpindex = i
            # binding whole word
            if (name[i].isupper()):
                while (i != (length - 1) and name[i + 1].islower()):
                    i = i + 1
            subname.append(name[tmpindex:(i + 1)])
            tmpindex = i + 1
        i = i + 1

    # append trailing lower string
    if tmpindex != length:
        subname.append(name[tmpindex:length])

    sublength = len(subname)
    i = 0
    while i < sublength:
        if (len(subname[i]) == 1 and subname[i].isupper()):
            # binding single upper string
            while(i != (sublength - 1) and len(subname[i + 1]) == 1 and subname[i + 1].isupper()):
                i = i + 1
                subname[i] = subname[i-1] + subname[i]
        if (len(fixedname) != 0 and fixedname[-1] != '_' and subname[i][0] != '_'):
            fixedname += '_'
        fixedname += subname[i].lower()
        i = i + 1
    return fixedname

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
        self.name = transform_to_C_name(self.name.replace('.', '_'))
        self.origname = name.leaf or name.name
        self.fixname = transform_to_C_name(self.origname.replace('.', '_'))
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

def make_name_array(name, prefix):
    return "oci_%s_%s_element" % (prefix, name)

def make_name(name, prefix):
    if prefix == name:
        return "oci_%s" % name
    return "oci_%s_%s" % (prefix, name)

def make_pointer(name, typ, prefix):
    if typ != 'object' and typ != 'mapStringString':
        return None
    return "%s *" % make_name(name, prefix)

def is_compound_object(typ):
    return typ in ['object', 'array', 'mapStringObject']

def is_numeric_type(typ):
    if typ.startswith("int") or typ.startswith("uint"):
        return True
    return typ in ["integer", "UID", "GID"]

def get_pointer(name, typ, prefix):
    ptr = make_pointer(name, typ, prefix)
    if ptr:
        return ptr
    if typ == "string":
        return "char *"
    if typ in ["mapStringString", "ArrayOfStrings"]:
        return "%s *" % typ
    return None

def append_C_code(obj, c_file, prefix):
    generate_C_parse(obj, c_file, prefix)
    generate_C_free(obj, c_file, prefix)
    generate_C_json(obj, c_file, prefix)

def generate_C_parse(obj, c_file, prefix):
    if not is_compound_object(obj.typ):
        return
    if obj.typ == 'object':
        obj_typename = typename = make_name(obj.name, prefix)
    elif obj.typ == 'array' or obj.typ == "mapStringObject":
        obj_typename = typename = make_name_array(obj.name, prefix)
        objs = obj.subtypobj
        if objs is None:
            return
    elif obj.typ == 'mapStringString':
        obj_typename = typename = make_name(obj.name, prefix)
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
    elif obj.typ == 'object' or ((obj.typ == 'array' or obj.typ == 'mapStringObject') and obj.subtypobj):
        nodes = obj.children if obj.typ == 'object' else obj.subtypobj

        required_to_check = []
        for i in (nodes or []):
            if obj.required and i.origname in obj.required and not is_numeric_type(i.typ):
                required_to_check.append(i)
            if i.typ == 'string':
                c_file.write('    {\n')
                read_value_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_string)' % i.origname, "ret->%s" % i.fixname, i.typ)
                c_file.write('    }\n')
            elif is_numeric_type(i.typ):
                c_file.write('    {\n')
                read_value_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_number)' % i.origname, "ret->%s" % i.fixname, i.typ)
                c_file.write('    }\n')
            if i.typ == 'boolean':
                c_file.write('    {\n')
                read_value_generator(c_file, 2, 'get_val (tree, "%s", yajl_t_true)' % i.origname, "ret->%s" % i.fixname, i.typ)
                c_file.write('    }\n')
            elif i.typ == 'object':
                typename = make_name(i.name, prefix)
                c_file.write('    ret->%s = make_%s (get_val (tree, "%s", yajl_t_object), ctx, err);\n' % (i.fixname, typename, i.origname))
                c_file.write("    if (ret->%s == NULL && *err != 0) {\n" % i.fixname)
                c_file.write("        free_%s (ret);\n" % obj_typename)
                c_file.write("        return NULL;\n")
                c_file.write("    }\n")
            elif i.typ == 'array' and i.subtypobj:
                typename = make_name_array(i.name, prefix)
                c_file.write('    {\n')
                c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_array);\n' % (i.origname))
                c_file.write('        if (tmp != NULL) {\n')
                c_file.write('            size_t i;\n')
                c_file.write('            ret->%s_len = YAJL_GET_ARRAY (tmp)->len;\n' % (i.fixname))
                c_file.write('            ret->%s = safe_malloc ((YAJL_GET_ARRAY (tmp)->len + 1) * sizeof (*ret->%s));\n' % (i.fixname, i.fixname))
                c_file.write('            for (i = 0; i < YAJL_GET_ARRAY (tmp)->len; i++) {\n')
                c_file.write('                yajl_val tmpsub = YAJL_GET_ARRAY (tmp)->values[i];\n')
                c_file.write('                ret->%s[i] = make_%s (tmpsub, ctx, err);\n' % (i.fixname, typename))
                c_file.write('            }\n')
                c_file.write('        }\n')
                c_file.write('    }\n')
            elif i.typ == 'array':
                c_file.write('    {\n')
                c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_array);\n' % (i.origname))
                c_file.write('        if (tmp != NULL) {\n')
                c_file.write('            size_t i;\n')
                c_file.write('            ret->%s_len = YAJL_GET_ARRAY (tmp)->len;\n' % (i.fixname))
                c_file.write('            ret->%s = safe_malloc ((YAJL_GET_ARRAY (tmp)->len + 1) * sizeof (*ret->%s));\n' % (i.fixname, i.fixname))
                c_file.write('            for (i = 0; i < YAJL_GET_ARRAY (tmp)->len; i++) {\n')
                c_file.write('                yajl_val tmpsub = YAJL_GET_ARRAY (tmp)->values[i];\n')
                read_value_generator(c_file, 4, 'tmpsub', "ret->%s[i]" % i.fixname, i.subtyp)
                c_file.write('            }\n')
                c_file.write('        }\n')
                c_file.write('    }\n')
            elif i.typ == 'mapStringObject':
                c_file.write('    {\n')
                c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_object);\n' % (i.origname))
                c_file.write('        if (tmp != NULL) {\n')
                c_file.write('            size_t i;\n')
                c_file.write('            ret->%s_len = YAJL_GET_OBJECT (tmp)->len;\n' % i.fixname)
                c_file.write('            ret->%s = safe_malloc ((YAJL_GET_OBJECT (tmp)->len + 1) * sizeof (*ret->%s));\n' % (i.fixname, i.fixname))
                c_file.write('            for (i = 0; i < YAJL_GET_OBJECT (tmp)->len; i++) {\n')
                c_file.write('                const char *key = YAJL_GET_OBJECT (tmp)->keys[i];\n')
                c_file.write('                if (key) {\n')
                c_file.write('                     ret->%s[i] = strdup(key) ? : "";\n' % i.fixname)
                c_file.write('                }\n')
                c_file.write('            }\n')
                c_file.write('        }\n')
                c_file.write('        else\n')
                c_file.write('        {\n')
                c_file.write('            ret->%s_len = 0;\n' % i.fixname)
                c_file.write('        }\n')
                c_file.write('    }\n')
            elif i.typ == 'mapStringString':
                c_file.write('    {\n')
                c_file.write('        yajl_val tmp = get_val (tree, "%s", yajl_t_object);\n' % (i.origname))
                c_file.write('        if (tmp != NULL) {\n')
                c_file.write('            ret->%s = read_map_string_string (tmp);\n' % (i.fixname))
                c_file.write('        }\n')
                c_file.write('    }\n')
        for i in required_to_check:
            c_file.write('    if (ret->%s == NULL) {\n' % i.fixname)
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

def generate_C_json(obj, c_file, prefix):
    if not is_compound_object(obj.typ):
        return
    if obj.typ == 'object':
        obj_typename = typename = make_name(obj.name, prefix)
    elif obj.typ == 'array' or obj.typ == "mapStringObject":
        obj_typename = typename = make_name_array(obj.name, prefix)
        objs = obj.subtypobj
        if objs is None:
            return
    elif obj.typ == 'mapStringString':
        obj_typename = typename = make_name(obj.name, prefix)
        objs = []


    c_file.write("bool gen_%s (yajl_gen g, %s *pstruct, struct libocispec_context *ctx, oci_parser_error *err) {\n" % (typename, typename))
    c_file.write("    bool stat = true;\n")
    c_file.write("    *err = 0;\n")
    c_file.write("    if (pstruct == NULL || g == NULL || err == NULL)\n")
    c_file.write("        return false;\n")

    if obj.typ == 'mapStringString':
        pass
    elif obj.typ == 'object' or ((obj.typ == 'array' or obj.typ == 'mapStringObject') and obj.subtypobj):
        c_file.write("    stat = reformat_start_map(g);\n")
        c_file.write("    if (!stat)\n")
        c_file.write("        return false;\n")
        nodes = obj.children if obj.typ == 'object' else obj.subtypobj

        for i in (nodes or []):
            if i.typ == 'string':
                c_file.write('    if (pstruct->%s) {\n' % i.fixname)
                c_file.write('        stat = reformat_map_key(g, "%s", strlen("%s"));\n' % (i.origname, i.origname))
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                json_value_generator(c_file, 2, "pstruct->%s" % i.fixname, 'g', i.typ)
                c_file.write("    }\n")

            elif is_numeric_type(i.typ):
                c_file.write('    if (pstruct->%s) {\n' % i.fixname)
                c_file.write('        stat = reformat_map_key(g, "%s", strlen("%s"));\n' % (i.origname, i.origname))
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                json_value_generator(c_file, 2, "pstruct->%s" % i.fixname, 'g', i.typ)
                c_file.write("    }\n")

            elif i.typ == 'boolean':
                c_file.write('    if (pstruct->%s) {\n' % i.fixname)
                c_file.write('        stat = reformat_map_key(g, "%s", strlen("%s"));\n' % (i.origname, i.origname))
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                json_value_generator(c_file, 2, "pstruct->%s" % i.fixname, 'g', i.typ)
                c_file.write("    }\n")

            elif i.typ ==  'object':
                typename = make_name(i.name, prefix)
                c_file.write('    if (pstruct->%s) {\n' % i.fixname)
                c_file.write('        stat = reformat_map_key(g, "%s", strlen("%s"));\n' % (i.origname, i.origname))
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                c_file.write('        stat = gen_%s(g, pstruct->%s, ctx, err);\n' % (typename, i.fixname))
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                c_file.write("    }\n")

            elif i.typ == 'array' and i.subtypobj:
                typename = make_name_array(i.name, prefix)
                c_file.write('    if (pstruct->%s) {\n' % i.fixname)
                c_file.write('        stat = reformat_map_key(g, "%s", strlen("%s"));\n' % (i.origname, i.origname))
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                c_file.write('        size_t i;\n')
                c_file.write('        stat = reformat_start_array(g);\n')
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                c_file.write('        for (i = 0; i < pstruct->%s_len; i++) {\n' % (i.fixname))
                c_file.write('            stat = gen_%s(g, pstruct->%s[i], ctx, err);\n' % (typename, i.fixname))
                c_file.write("            if (!stat)\n")
                c_file.write("                return false;\n")
                c_file.write('        }\n')
                c_file.write('        stat = reformat_end_array(g);\n')
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                c_file.write('    }\n')

            elif i.typ == 'array':
                c_file.write('    if (pstruct->%s) {\n' % i.fixname)
                c_file.write('        stat = reformat_map_key(g, "%s", strlen("%s"));\n' % (i.origname, i.origname))
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                c_file.write('        size_t i;\n')
                c_file.write('        stat = reformat_start_array(g);\n')
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                c_file.write('        for (i = 0; i < pstruct->%s_len; i++) {\n' % (i.fixname))
                json_value_generator(c_file, 3, "pstruct->%s[i]" % i.fixname, 'g', i.subtyp)
                c_file.write('        }\n')
                c_file.write('        stat = reformat_end_array(g);\n')
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                c_file.write('    }\n')
            elif i.typ == 'mapStirngString':
                c_file.write('    if (pstruct->%s) {\n' % i.fixname)
                c_file.write('        stat = reformat_map_key(g, "%s", strlen("%s"));\n' % (i.origname, i.origname))
                c_file.write("        if (!stat)\n")
                c_file.write("            return false;\n")
                json_value_generator(c_file, 2, "pstruct->%s" % i.fixname, 'g', i.typ)
                c_file.write("    }\n")

        c_file.write("    stat = reformat_end_map(g);\n")
        c_file.write("    if (!stat)\n")
        c_file.write("        return false;\n")
    c_file.write('    return true;\n')
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

def json_value_generator(c_file, level, src, dst, typ):
    if typ == 'mapStringString':
        c_file.write('%sstat = gen_map_string_string(%s, %s);\n' % ('    ' * (level), dst, src))
        c_file.write("%sif (!stat)\n" % ('    ' * (level)))
        c_file.write("%sreturn false;\n" % ('    ' * (level + 1)))
    elif typ == 'string':
        c_file.write('%sstat = reformat_string(%s, %s, strlen(%s));\n' % ('    ' * (level), dst, src, src))
        c_file.write("%sif (!stat)\n" % ('    ' * (level)))
        c_file.write("%sreturn false;\n" % ('    ' * (level + 1)))

    elif is_numeric_type(typ):
        c_file.write('%sstat = reformat_integer(%s, %s);\n' % ('    ' * (level), dst, src))
        c_file.write("%sif (!stat)\n" % ('    ' * (level)))
        c_file.write("%sreturn false;\n" % ('    ' * (level + 1)))

    elif typ == 'boolean':
        c_file.write('%sstat = reformat_boolean(%s, 1);\n' % ('    ' * (level), dst))
        c_file.write("%sif (!stat)\n" % ('    ' * (level)))
        c_file.write("%sreturn false;\n" % ('    ' * (level + 1)))

def generate_C_free(obj, c_file, prefix):
    if not is_compound_object(obj.typ) and obj.typ != 'mapStringString':
        return

    typename = make_name(obj.name, prefix)
    if obj.typ == 'mapStringString':
        objs = []
    if obj.typ == 'object':
        objs = obj.children
    elif obj.typ == 'array' or obj.typ == 'mapStringObject':
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
            free_func = make_name(i.name, prefix)
            c_file.write("    free_%s (ptr->%s);\n" % (free_func, i.fixname))
            c_file.write("    ptr->%s = NULL;\n" % (i.fixname))
        elif i.typ == 'array' or i.typ == 'mapStringObject':
            if i.subtyp == 'mapStringString':
                free_func = make_name_array(i.name, prefix)
                c_file.write("    if (ptr->%s) {\n" % i.fixname)
                c_file.write("        size_t i;\n")
                c_file.write("        for (i = 0; i < ptr->%s_len; i++) {\n" % i.fixname)
                c_file.write("            free_cells (ptr->%s[i]);\n" % (i.fixname))
                c_file.write("        }\n")
                c_file.write("        ptr->%s = NULL;\n" % (i.fixname))
                c_file.write("    }\n")
            elif i.subtyp == 'string':
                free_func = make_name_array(i.name, prefix)
                c_file.write("    if (ptr->%s) {\n" % i.fixname)
                c_file.write("        size_t i;\n")
                c_file.write("        for (i = 0; i < ptr->%s_len; i++) {\n" % i.fixname)
                c_file.write("            free (ptr->%s[i]);\n" % (i.fixname))
                c_file.write("        }\n")
                c_file.write("        ptr->%s = NULL;\n" % (i.fixname))
                c_file.write("    }\n")
            elif i.subtypobj is not None:
                free_func = make_name_array(i.name, prefix)
                c_file.write("    if (ptr->%s) {\n" % i.fixname)
                c_file.write("        size_t i;\n")
                c_file.write("        for (i = 0; i < ptr->%s_len; i++)\n" % i.fixname)
                c_file.write("            free_%s (ptr->%s[i]);\n" % (free_func, i.fixname))
                c_file.write("        free (ptr->%s);\n" % i.fixname)
                c_file.write("        ptr->%s = NULL;\n" % (i.fixname))
                c_file.write("    }\n")

            c_typ = get_pointer(i.name, i.subtypobj, prefix)
            if c_typ == None:
                continue
            if i.subobj is not None:
                c_typ = c_typ + "_element"
            c_file.write("    free_%s (ptr->%s);\n" % (c_typ, i.fixname))
            c_file.write("    ptr->%s = NULL;\n" % (i.fixname))
        else: # not array
            typename = make_name(i.name, prefix)
            if i.typ == 'string':
                c_file.write("    free (ptr->%s);\n" % (i.fixname))
                c_file.write("    ptr->%s = NULL;\n" % (i.fixname))
            elif i.typ == 'object':
                c_file.write("    if (ptr->%s)\n" % (i.fixname))
                c_file.write("        free_%s (ptr->%s);\n" % (typename, i.fixname))
                c_file.write("    ptr->%s = NULL;\n" % (i.fixname))
    c_file.write("    free (ptr);\n")
    c_file.write("}\n\n")

def append_type_C_header(obj, header, prefix):
    if obj.typ == 'mapStringString':
        typename = make_name(obj.name, prefix)
        header.write("typedef string_cells %s;\n\n" % typename)
    elif obj.typ == 'array' or obj.typ == 'mapStringObject':
        if not obj.subtypobj:
            return
        header.write("typedef struct {\n")
        for i in obj.subtypobj:
            if i.typ == 'array' or i.typ == 'mapStringObject':
                c_typ = make_pointer(i.name, i.subtyp, prefix) or c_types_mapping[i.subtyp]
                if i.subtypobj is not None:
                    c_typ = make_name_array(i.name, prefix)

                if not is_compound_object(i.subtyp):
                    header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.fixname))
                else:
                    header.write("    %s **%s;\n" % (c_typ, i.fixname))
                header.write("    size_t %s;\n\n" % (i.fixname + "_len"))
            else:
                c_typ = make_pointer(i.name, i.typ, prefix) or c_types_mapping[i.typ]
                header.write("    %s%s%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.fixname))
        typename = make_name_array(obj.name, prefix)
        header.write("}\n%s;\n\n" % typename)
        header.write("void free_%s (%s *ptr);\n\n" % (typename, typename))
        header.write("%s *make_%s (yajl_val tree, struct libocispec_context *ctx, oci_parser_error *err);\n\n" % (typename, typename))
    elif obj.typ == 'object':
        header.write("typedef struct {\n")
        for i in (obj.children or []):
            if i.typ == 'array' or i.typ == 'mapStringObject':
                if i.subtypobj is not None:
                    c_typ = make_name_array(i.name, prefix)
                else:
                    c_typ = make_pointer(i.name, i.subtyp, prefix) or c_types_mapping[i.subtyp]

                if i.subtyp == 'mapStringString':
                    header.write("    %s **%s;\n" % (make_name_array(i.name, prefix), i.fixname))
                elif not is_compound_object(i.subtyp):
                    header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.fixname))
                else:
                    header.write("    %s%s**%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.fixname))
                header.write("    size_t %s;\n\n" % (i.fixname + "_len"))
            else:
                c_typ = make_pointer(i.name, i.typ, prefix) or c_types_mapping[i.typ]
                header.write("    %s%s%s;\n\n" % (c_typ, " " if '*' not in c_typ else "", i.fixname))

        typename = make_name(obj.name, prefix)
        header.write("}\n%s;\n\n" % typename)
        header.write("void free_%s (%s *ptr);\n\n" % (typename, typename))
        header.write("%s *make_%s (yajl_val tree, struct libocispec_context *ctx, oci_parser_error *err);\n\n" % (typename, typename))

def get_ref(src, ref):
    if '#/' in ref:
        f, r = ref.split("#/")
    else:
        f = ref
        r = ""

    if f == "":
        cur = src
    else:
        with open(f) as i:
            cur = src = json.loads(i.read())
    if r != "":
        for j in r.split('/'):
            basic_types = [
                "int8", "int16", "int32", "int64",
                "uint8", "uint16", "uint32", "uint64", "UID", "GID",
                "mapStringString", "ArrayOfStrings", "mapStringObject"
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
    elif "oneOf" in cur:
        cur = cur['oneOf'][0]
        if '$ref' in cur:
            return resolve_type(name, src, cur)
        else:
            typ = cur['type']
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
            anychildren = scan_list(name, src, cur["items"]['anyOf'])
            subtyp = anychildren[0].typ
            children = anychildren[0].children
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
    elif typ == 'mapStringObject':
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

def scan_main(schema, prefix):
    return Node(Name(prefix), "object", scan_properties(Name(""), schema, schema))

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

def generate_C_header(structs, header, prefix):
    header.write("/* autogenerated file */\n")
    header.write("#ifndef %s_SCHEMA_H\n" % prefix.upper())
    header.write("# define %s_SCHEMA_H\n\n" % prefix.upper())
    header.write("# include <sys/types.h>\n")
    header.write("# include <stdint.h>\n")
    header.write("# include \"oci_json_common.h\"\n\n")

    for i in structs:
        append_type_C_header(i, header, prefix)
    header.write("oci_%s *oci_%s_parse_file (const char *filename, struct libocispec_context *ctx, oci_parser_error *err);\n\n" % (prefix, prefix))
    header.write("oci_%s *oci_%s_parse_file_stream (FILE *stream, struct libocispec_context *ctx, oci_parser_error *err);\n\n" % (prefix, prefix))
    header.write("oci_%s *oci_%s_parse_data (const char *jsondata, struct libocispec_context *ctx, oci_parser_error *err);\n\n" % (prefix, prefix))
    header.write("char *oci_%s_generate_json (oci_%s *%s, struct libocispec_context *ctx, oci_parser_error *err);\n\n" % (prefix, prefix, prefix))
    header.write("#endif\n")

def generate_C_code(structs, header_name, c_file, prefix):
    c_file.write("// autogenerated file\n")
    c_file.write("# ifndef _GNU_SOURCE\n")
    c_file.write("#  define _GNU_SOURCE\n")
    c_file.write("# endif\n")
    c_file.write('#include <string.h>\n')
    c_file.write('#include <read-file.h>\n')
    c_file.write('#include "%s"\n\n' % header_name)

    for i in structs:
        append_C_code(i, c_file, prefix)

def generate_C_epilogue(c_file, prefix):
    c_file.write("""\n
oci_%s *oci_%s_parse_file (const char *filename, struct libocispec_context *ctx, oci_parser_error *err) {
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

    oci_%s *%s = make_oci_%s (tree, ctx, err);
    yajl_tree_free (tree);
    return %s;
}
""" % (prefix, prefix, prefix, prefix, prefix, prefix))

    c_file.write("""\n
oci_%s *oci_%s_parse_file_stream (FILE *stream, struct libocispec_context *ctx, oci_parser_error *err) {
    yajl_val tree;
    size_t filesize;
    *err = NULL;
    struct libocispec_context tmp_ctx;
    if (!ctx) {
       ctx = &tmp_ctx;
       memset (&tmp_ctx, 0, sizeof (tmp_ctx));
    }
    char *content = fread_file (stream, &filesize);
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

    oci_%s *%s = make_oci_%s (tree, ctx, err);
    yajl_tree_free (tree);
    return %s;
}
""" % (prefix, prefix, prefix, prefix, prefix, prefix))

    c_file.write("""\n
oci_%s *oci_%s_parse_data (const char *jsondata, struct libocispec_context *ctx, oci_parser_error *err) {
    yajl_val tree;
    *err = NULL;
    struct libocispec_context tmp_ctx;
    if (!ctx) {
       ctx = &tmp_ctx;
       memset (&tmp_ctx, 0, sizeof (tmp_ctx));
    }
    char errbuf[1024];
    if (jsondata == NULL) {
        *err = strdup ("oci data cannot be NULL");
        return NULL;
    }
    tree = yajl_tree_parse (jsondata, errbuf, sizeof(errbuf));
    if (tree == NULL) {
        *err = strdup ("cannot parse the oci data");
        return NULL;
    }

    oci_%s *%s = make_oci_%s (tree, ctx, err);
    yajl_tree_free (tree);
    return %s;
}
""" % (prefix, prefix, prefix, prefix, prefix, prefix))

    c_file.write("""\n
char *oci_%s_generate_json (oci_%s *pstruct, struct libocispec_context *ctx, oci_parser_error *err) {
    yajl_gen g = NULL;
    const unsigned char *gen_buf = NULL;
    char *json_buf = NULL;
    size_t gen_len = 0;
    *err = NULL;
    if (!pstruct) {
        *err = strdup("NULL input");
        goto out;
    }
    struct libocispec_context tmp_ctx;
    if (!ctx) {
        ctx = &tmp_ctx;
        memset (&tmp_ctx, 0, sizeof (tmp_ctx));
    }\n
    if (!json_gen_init(&g)) {
        *err = strdup("Json_gen init failed");
        goto out;
    }\n
    if (!gen_oci_%s(g, pstruct, ctx, err)) {
        *err = strdup("Failed to generate json");
        goto free_out;
    }\n
    yajl_gen_get_buf(g, &gen_buf, &gen_len);
    if (!gen_buf) {
        *err = strdup("Error to get generated json");
        goto free_out;
    }\n
    json_buf = safe_malloc(gen_len + 1);
    memcpy(json_buf, gen_buf, gen_len);
    json_buf[gen_len] = '\\0';\n
free_out:
    yajl_gen_clear(g);
    yajl_gen_free(g);
out:
    return json_buf;
}
""" % (prefix, prefix, prefix))

def generate(schema_json, header_name, header_file, c_file, prefix):
    tree = scan_main(schema_json, prefix)
    # we could do this in scan_main, but let's work on tree that is easier
    # to access.
    structs = flatten(tree, [])
    generate_C_header(structs, header_file, prefix)
    generate_C_code(structs, header_name, c_file, prefix)
    generate_C_epilogue(c_file, prefix)

def generate_common_C_header(header_file):
    header_file.write("""// autogenerated file
#ifndef _OCI_COMMON_H
# define _OCI_COMMON_H\n
# include <stdbool.h>
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <yajl/yajl_tree.h>
# include <yajl/yajl_gen.h>\n
# undef linux
# define LIBOCISPEC_OPTIONS_STRICT 1
typedef char *oci_parser_error;\n
typedef struct {\n    char **keys;\n    char **values;\n    size_t len;\n} string_cells;\n
struct libocispec_context {\n    int options;\n    FILE *stderr;\n};\n
/* non-zero when we're reformatting a stream */
# define s_streamReformat 0
# define GEN_AND_RETURN(func) {                  \\
    yajl_gen_status __stat = func;                    \\
    if (__stat == yajl_gen_generation_complete && s_streamReformat) {\\
        yajl_gen_reset(g, \"\\n\");                \\
        __stat = func;                      \\
    }                             \\
    return __stat == yajl_gen_status_ok; \\
}\n
int reformat_integer(void *ctx, long long int num);\n
int reformat_double(void *ctx, double num);\n
int reformat_number(void *ctx, const char *str, size_t len);\n
int reformat_string(void *ctx, const unsigned char *str, size_t len);\n
int reformat_null(void *ctx);\n
int reformat_boolean(void *ctx, int boolean);\n
int reformat_map_key(void *ctx, const unsigned char *str, size_t len);\n
int reformat_start_map(void *ctx);\n
int reformat_end_map(void *ctx);\n
int reformat_start_array(void *ctx);\n
int reformat_end_array(void *ctx);\n
int gen_map_string_string(void *ctx, string_cells *cells);\n
bool json_gen_init(yajl_gen *g);\n
yajl_val get_val(yajl_val tree, const char *name, yajl_type type);\n
string_cells *read_map_string_string (yajl_val src);\n
void free_cells (string_cells *cells);\n
void *safe_malloc (size_t size);\n
#endif
""")

def generate_common_C_code(c_file):
    c_file.write("""// autogenerated file
#include "oci_json_common.h"\n
int reformat_integer(void *ctx, long long int num) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_integer(g,num));
}\n
int reformat_double(void *ctx, double num) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_double(g,num));
}\n
int reformat_number(void *ctx, const char *str, size_t len) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_number(g, str, len));
}\n
int reformat_string(void *ctx, const unsigned char *str, size_t len) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_string(g, str, len));
}\n
int reformat_null(void *ctx) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_null(g));
}\n
int reformat_boolean(void *ctx, int boolean) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_bool(g, boolean));
}\n
int reformat_map_key(void *ctx, const unsigned char *str, size_t len) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_string(g, str, len));
}\n
int reformat_start_map(void *ctx) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_map_open(g));
}\n
int reformat_end_map(void *ctx) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_map_close(g));
}\n
int reformat_start_array(void *ctx) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_array_open(g));
}\n
int reformat_end_array(void *ctx) {
    yajl_gen g = (yajl_gen) ctx;
    GEN_AND_RETURN(yajl_gen_array_close(g));
}\n
int gen_map_string_string(void *ctx, string_cells *cells) {
    bool stat = true;
    yajl_gen g = (yajl_gen) ctx;
    size_t i = 0;
    if (!cells)
        return false;\n
    stat = reformat_start_map(g);
    if (!stat)
        return false;\n
    for (i = 0; i < cells->len; i++) {
        stat = reformat_map_key(g, cells->keys[i], strlen(cells->keys[i]));
        if (!stat)
            return false;
        stat = reformat_string(g, cells->values[i], strlen(cells->values[i]));
        if (!stat)
            return false;
    }\n
    stat = reformat_end_map(g);
    if (!stat)
        return false;
    return true;
}\n
bool json_gen_init(yajl_gen *g) {
    *g = yajl_gen_alloc(NULL);
    if (NULL == *g)
        return false;\n
    yajl_gen_config(*g, yajl_gen_beautify, 1);
    yajl_gen_config(*g, yajl_gen_validate_utf8, 1);
    return true;
}\n
yajl_val get_val(yajl_val tree, const char *name, yajl_type type) {
    const char *path[] = { name, NULL };
    return yajl_tree_get (tree, path, type);
}\n
void free_cells (string_cells *cells) {
    if (cells) {
        size_t i;
        for (i = 0; i < cells->len; i++) {
            free (cells->keys[i]);
            free (cells->values[i]);
        }
        free (cells);
    }
}\n
void *safe_malloc (size_t size) {
    void *ret = malloc (size);
    if (ret == NULL)
        abort ();
    memset (ret, 0, size);
    return ret;
}\n
string_cells *read_map_string_string (yajl_val src) {
    string_cells *ret = NULL;
    if (src != NULL) {
        size_t i;
        ret = safe_malloc (sizeof (string_cells));
        ret->len = YAJL_GET_OBJECT (src)->len;
        ret->keys = safe_malloc ((YAJL_GET_OBJECT (src)->len + 1) * sizeof (char *));
        ret->values = safe_malloc ((YAJL_GET_OBJECT (src)->len + 1) * sizeof (char *));
        for (i = 0; i < YAJL_GET_OBJECT (src)->len; i++) {
            yajl_val srcsub = YAJL_GET_OBJECT (src)->values[i];
            ret->keys[i] = strdup (YAJL_GET_OBJECT (src)->keys[i] ? : "");
            if (srcsub)
                ret->values[i] = strdup (YAJL_GET_STRING (srcsub) ? : "");
            else
                ret->values[i] = NULL;
        }
    }
    return ret;
}
""")

def generate_common_file(header_file, c_file):
    generate_common_C_header(header_file)
    generate_common_C_code(c_file)

if __name__ == "__main__":
    schema_file = sys.argv[1]
    header = sys.argv[2]
    c_source = sys.argv[3]
    prefix = sys.argv[4]
    oldcwd = os.getcwd()
    with open("src/oci_json_common.h", "w") as common_h_file, open("src/oci_json_common.c", "w") as common_c_file:
        generate_common_file(common_h_file, common_c_file)
    with open(header + ".tmp", "w") as header_file, open(c_source + ".tmp", "w") as c_file:
        os.chdir(os.path.dirname(schema_file))
        with open(os.path.basename(schema_file)) as schema:
            schema_json = json.loads(schema.read())
        generate(schema_json, os.path.basename(header), header_file, c_file, prefix)
    os.chdir(oldcwd)
    os.rename(header + ".tmp", header)
    os.rename(c_source + ".tmp", c_source)
