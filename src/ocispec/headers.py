# -*- coding: utf-8 -*-
#
# libocispec - a C library for parsing OCI spec files.
#
# Copyright (C) Huawei Technologies., Ltd. 2018-2020.
# Copyright (C) 2017, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
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

def append_header_arr(obj, header, prefix):
    '''
    Description: Write c header file of array
    Interface: None
    History: 2019-06-17
    '''
    if not obj.subtypobj or obj.subtypname:
        return

    header.append("typedef struct {\n")
    for i in obj.subtypobj:
        if i.typ == 'array':
            c_typ = helpers.get_prefixed_pointer(i.name, i.subtyp, prefix) or \
                helpers.get_map_c_types(i.subtyp)
            if i.subtypobj is not None:
                c_typ = helpers.get_name_substr(i.name, prefix)

            if not helpers.is_compound_type(i.subtyp):
                header.append(f"    {c_typ}{' ' if '*' not in c_typ else ''}*{i.fixname};\n")
            else:
                header.append(f"    {c_typ} **{i.fixname};\n")
            header.append(f"    size_t {i.fixname + '_len'};\n\n")
        else:
            c_typ = helpers.get_prefixed_pointer(i.name, i.typ, prefix) or \
                helpers.get_map_c_types(i.typ)
            header.append(f"    {c_typ}{' ' if '*' not in c_typ else ''}{i.fixname};\n")
    for i in obj.subtypobj:
        if helpers.is_numeric_type(i.typ) or i.typ == 'boolean':
            header.append(f"    unsigned int {i.fixname}_present : 1;\n")
    typename = helpers.get_name_substr(obj.name, prefix)
    header.append(f"}}\n{typename};\n\n")
    header.append(f"void free_{typename} ({typename} *ptr);\n\n")
    header.append(f"{typename} *make_{typename} (yajl_val tree, const struct parser_context *ctx, parser_error *err);\n\n")


def append_header_map_str_obj(obj, header, prefix):
    '''
    Description: Write c header file of mapStringObject
    Interface: None
    History: 2019-06-17
    '''
    child = obj.children[0]
    header.append("typedef struct {\n")
    header.append("    char **keys;\n")
    if helpers.valid_basic_map_name(child.typ):
        c_typ = helpers.get_prefixed_pointer("", child.typ, "")
    elif child.subtypname:
        c_typ = child.subtypname +  " *"
    else:
        c_typ = helpers.get_prefixed_pointer(child.name, child.typ, prefix)
    header.append(f"    {c_typ}{' ' if '*' not in c_typ else ''}*{child.fixname};\n")
    header.append("    size_t len;\n")


def append_header_child_arr(child, header, prefix):
    '''
    Description: Write c header file of array of child
    Interface: None
    History: 2019-06-17
    '''
    if helpers.get_map_c_types(child.subtyp) != "":
        c_typ = helpers.get_map_c_types(child.subtyp)
    elif helpers.valid_basic_map_name(child.subtyp):
        c_typ = f'{helpers.make_basic_map_name(child.subtyp)} *'
    elif child.subtypname is not None:
        c_typ = child.subtypname
    elif child.subtypobj is not None:
        c_typ = helpers.get_name_substr(child.name, prefix)
    else:
        c_typ = helpers.get_prefixed_pointer(child.name, child.subtyp, prefix)

    dflag = ""
    if child.nested_array:
        dflag = "*"

    if helpers.valid_basic_map_name(child.subtyp):
        header.append(f"    {helpers.make_basic_map_name(child.subtyp)} **{child.fixname};\n")
    elif not helpers.is_compound_type(child.subtyp):
        header.append(f"    {c_typ}{' ' if '*' not in c_typ else ''}*{dflag}{child.fixname};\n")
    else:
        header.append(f"    {c_typ}{' ' if '*' not in c_typ else ''}**{dflag}{child.fixname};\n")

    if child.nested_array and not helpers.valid_basic_map_name(child.subtyp):
        header.append(f"    size_t *{child.fixname + '_item_lens'};\n")

    header.append(f"    size_t {child.fixname + '_len'};\n\n")

def append_header_child_others(child, header, prefix):
    '''
    Description: Write c header file of others of child
    Interface: None
    History: 2019-06-17
    '''
    if helpers.get_map_c_types(child.typ) != "":
        c_typ = helpers.get_map_c_types(child.typ)
    elif helpers.valid_basic_map_name(child.typ):
        c_typ = f'{helpers.make_basic_map_name(child.typ)} *'
    elif child.subtypname:
        c_typ = helpers.get_prefixed_pointer(child.subtypname, child.typ, "")
    else:
        c_typ = helpers.get_prefixed_pointer(child.name, child.typ, prefix)
    header.append(f"    {c_typ}{' ' if '*' not in c_typ else ''}{child.fixname};\n\n")


def append_type_c_header(obj, header, prefix):
    '''
    Description: Write c header file
    Interface: None
    History: 2019-06-17
    '''
    if not helpers.is_compound_type(obj.typ):
        return

    if obj.typ == 'array':
        append_header_arr(obj, header, prefix)
        return

    if obj.typ == 'mapStringObject':
        if obj.subtypname is not None:
            return
        append_header_map_str_obj(obj, header, prefix)
    elif obj.typ == 'object':
        if obj.subtypname is not None:
            return
        header.append("typedef struct {\n")
        if obj.children is None:
            header.append("    char unuseful; // unuseful definition to avoid empty struct\n")
        present_tags = []
        for i in obj.children or []:
            if helpers.is_numeric_type(i.typ) or i.typ == 'boolean':
                present_tags.append(f"    unsigned int {i.fixname}_present : 1;\n")
            if i.typ == 'array':
                append_header_child_arr(i, header, prefix)
            else:
                append_header_child_others(i, header, prefix)
        if obj.children is not None:
            header.append("    yajl_val _residual;\n")
        if len(present_tags) > 0:
            header.append("\n")
            for tag in present_tags:
                header.append(tag)
    typename = helpers.get_prefixed_name(obj.name, prefix)
    header.append(f"}}\n{typename};\n\n")
    header.append(f"void free_{typename} ({typename} *ptr);\n\n")
    header.append(f"{typename} *clone_{typename} ({typename} *src);\n")
    header.append(f"{typename} *make_{typename} (yajl_val tree, const struct parser_context *ctx, parser_error *err);\n\n")
    header.append(f"yajl_gen_status gen_{typename} (yajl_gen g, const {typename} *ptr, const struct parser_context *ctx, parser_error *err);\n\n")

def header_reflect_top_array(obj, prefix, header):
    c_typ = helpers.get_prefixed_pointer(obj.name, obj.subtyp, prefix) or \
        helpers.get_map_c_types(obj.subtyp)
    if obj.subtypobj is not None:
        if obj.nested_array and obj.subtypname is not None:
            c_typ = obj.subtypname + " *"
        else:
            c_typ = helpers.get_name_substr(obj.name, prefix) + " *"
    if c_typ == "":
        return

    typename = helpers.get_top_array_type_name(obj.name, prefix)
    header.append("typedef struct {\n")
    if obj.nested_array:
        header.append(f"    {c_typ}{' ' if '*' not in c_typ else ''}**items;\n")
        header.append("    size_t *subitem_lens;\n\n")
    else:
        header.append(f"    {c_typ}{' ' if '*' not in c_typ else ''}*items;\n")
    header.append("    size_t len;\n\n")
    header.append(f"}}\n{typename};\n\n")


    header.append(f"void free_{typename} ({typename} *ptr);\n\n")
    header.append(f"{typename} *{typename}_parse_file(const char *filename, const struct "\
        "parser_context *ctx, parser_error *err);\n\n")
    header.append(f"{typename} *{typename}_parse_file_stream(FILE *stream, const struct "\
        "parser_context *ctx, parser_error *err);\n\n")
    header.append(f"{typename} *{typename}_parse_data(const char *jsondata, const struct "\
        "parser_context *ctx, parser_error *err);\n\n")
    header.append(f"char *{typename}_generate_json(const {typename} *ptr, "\
        "const struct parser_context *ctx, parser_error *err);\n\n")

def header_reflect(structs, schema_info, header):
    '''
    Description: Reflection header files
    Interface: None
    History: 2019-06-17
    '''
    prefix = schema_info.prefix
    header.append(f"// Generated from {schema_info.name.basename}. Do not edit!\n")
    header.append(f"#ifndef {prefix.upper()}_SCHEMA_H\n")
    header.append(f"#define {prefix.upper()}_SCHEMA_H\n\n")
    header.append("#include <sys/types.h>\n")
    header.append("#include <stdint.h>\n")
    header.append("#include \"ocispec/json_common.h\"\n")
    if schema_info.refs:
        for ref in schema_info.refs.keys():
            header.append(f"#include \"ocispec/{ref}\"\n")
    header.append("\n#ifdef __cplusplus\n")
    header.append("extern \"C\" {\n")
    header.append("#endif\n\n")

    for i in structs:
        append_type_c_header(i, header, prefix)
    length = len(structs)
    toptype = structs[length - 1].typ if length != 0 else ""
    if toptype == 'object':
        header.append(f"{prefix} *{prefix}_parse_file (const char *filename, const struct parser_context *ctx, "\
            "parser_error *err);\n\n")
        header.append(f"{prefix} *{prefix}_parse_file_stream (FILE *stream, const struct parser_context *ctx, "\
            "parser_error *err);\n\n")
        header.append(f"{prefix} *{prefix}_parse_data (const char *jsondata, const struct parser_context *ctx, "\
            "parser_error *err);\n\n")
        header.append(f"char *{prefix}_generate_json (const {prefix} *ptr, const struct parser_context *ctx, "\
            "parser_error *err);\n\n")
    elif toptype == 'array':
        header_reflect_top_array(structs[length - 1], prefix, header)

    header.append("#ifdef __cplusplus\n")
    header.append("}\n")
    header.append("#endif\n\n")
    header.append("#endif\n\n")
