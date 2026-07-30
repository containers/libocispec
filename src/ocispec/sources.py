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
import json_api


def emit(c_file, code, indent=0):
    """Emit code with proper indentation.

    Args:
        c_file: List to append code lines to
        code: Multi-line string (will be dedented)
        indent: Number of 2-space indentation levels
    """
    prefix = '  ' * indent
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
        indent: Number of 2-space indentation levels
    """
    prefix = '  ' * indent
    c_file.append(f"{prefix}free ({ptr}->{field});\n")
    c_file.append(f"{prefix}{ptr}->{field} = NULL;\n")


def null_check_return(c_file, var, indent=0):
    """Generate NULL check with return NULL.

    Args:
        c_file: List to append code lines to
        var: Variable to check (can be expression like 'ret->field' or 'ret->field[i]')
        indent: Number of 2-space indentation levels
    """
    prefix = '  ' * indent
    c_file.append(f"{prefix}if ({var} == NULL)\n")
    c_file.append(f"{prefix}  return NULL;\n")


def calloc_with_check(c_file, dest, count, sizeof_expr, indent=0):
    """Generate calloc call with NULL check.

    Args:
        c_file: List to append code lines to
        dest: Destination variable
        count: Count expression for calloc
        sizeof_expr: sizeof expression (the content inside sizeof())
        indent: Number of 2-space indentation levels
    """
    prefix = '  ' * indent
    c_file.append(f"{prefix}{dest} = calloc ({count}, sizeof ({sizeof_expr}));\n")
    c_file.append(f"{prefix}if ({dest} == NULL)\n")
    c_file.append(f"{prefix}  return NULL;\n")


def check_gen_status(c_file, indent=0):
    """Generate JSON gen status check with error return.

    Args:
        c_file: List to append code lines to
        indent: Number of 2-space indentation levels
    """
    prefix = '  ' * indent
    c_file.append(f"{prefix}if (stat != {json_api.GEN_STATUS_OK})\n")
    c_file.append(f"{prefix}  GEN_SET_ERROR_AND_RETURN (stat, err);\n")


def do_read_value(c_file, src_expr, dest_expr, typ, origname, obj_typename, indent=1):
    """Wrap read_val_generator in a do-while(0) block.

    Args:
        c_file: Output file list
        src_expr: Source expression (e.g., 'get_val (tree, "name", json_api.TYPE_STRING)')
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
      }} while (0);
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


def emit_invalid_type_check(c_file, check_expr=None, indent=0):
    """Emit JSON type validation with error return.

    Args:
        c_file: List to append code lines to
        check_expr: Full C check expression (default: json_api.is_number('val'))
        indent: Number of 4-space indentation levels
    """
    if check_expr is None:
        check_expr = json_api.is_number('val')
    emit(c_file, f'''
        if (! {check_expr})
          {{
            *err = strdup ("invalid type");
            return NULL;
          }}
    ''', indent=indent)


# JSON generation helpers

def emit_gen_key(c_file, key, indent=0):
    """Emit JSON gen_string for an object key.

    Args:
        c_file: List to append code lines to
        key: Key string to generate
        indent: Number of 4-space indentation levels
    """
    key_len = len(key)
    emit(c_file, f'''
        stat = {json_api.gen_string('g', f'"{key}"', f'{key_len} /* strlen ("{key}") */')};
    ''', indent=indent)


def emit_gen_key_with_check(c_file, key, indent=0):
    """Emit JSON gen_string for an object key and check status."""
    emit_gen_key(c_file, key, indent=indent)
    check_gen_status(c_file, indent=indent)


def emit_gen_map_open(c_file, indent=0):
    """Emit gen_map_open call.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        stat = {json_api.gen_map_open('g')};
    ''', indent=indent)


def emit_gen_map_close(c_file, indent=0):
    """Emit gen_map_close call.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        stat = {json_api.gen_map_close('g')};
    ''', indent=indent)


def emit_gen_array_open(c_file, indent=0):
    """Emit gen_array_open call.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        stat = {json_api.gen_array_open('g')};
    ''', indent=indent)


def emit_gen_array_close(c_file, indent=0):
    """Emit gen_array_close call.

    Args:
        c_file: List to append code lines to
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        stat = {json_api.gen_array_close('g')};
    ''', indent=indent)


def emit_beautify_off(c_file, condition='!len', indent=0):
    """Emit beautify disable.

    Args:
        c_file: List to append code lines to
        condition: Condition for disabling beautify
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        if ({condition} && !(ctx->options & OPT_GEN_SIMPLIFY))
            {json_api.gen_config('g', json_api.GEN_BEAUTIFY, '0')};
    ''', indent=indent)


def emit_beautify_on(c_file, condition='!len', indent=0):
    """Emit beautify enable.

    Args:
        c_file: List to append code lines to
        condition: Condition for enabling beautify
        indent: Number of 4-space indentation levels
    """
    emit(c_file, f'''
        if ({condition} && !(ctx->options & OPT_GEN_SIMPLIFY))
            {json_api.gen_config('g', json_api.GEN_BEAUTIFY, '1')};
    ''', indent=indent)


def emit_array_parse_preamble(c_file, obj):
    """Emit the common preamble for array parsing.

    Emits the do/get_val/array_check/len/values/calloc block shared by
    ObjectArrayHandler, PrimitiveArrayHandler, and BasicMapArrayHandler.
    """
    emit(c_file, f'''
        do
          {{
            {json_api.VAL_TYPE} tmp = get_val (tree, "{obj.origname}", {json_api.TYPE_ARRAY});
            if (tmp != NULL && {json_api.array_check('tmp')})
              {{
                size_t i;
                size_t len = {json_api.array_len('tmp')};
                ret->{obj.fixname}_len = len;
    ''', indent=1)
    calloc_with_check(c_file, f'ret->{obj.fixname}', 'len + 1', f'*ret->{obj.fixname}', indent=3)
    if obj.nested_array:
        calloc_with_check(c_file, f'ret->{obj.fixname}_item_lens', 'len + 1', 'size_t', indent=3)


def emit_array_gen_preamble(c_file, obj, len_indent='  '):
    """Emit the common preamble for array generation.

    Emits the if-OPT_GEN + gen_key + len setup + beautify_off + array_open +
    check_gen_status block shared by ObjectArrayHandler, PrimitiveArrayHandler,
    and BasicMapArrayHandler.

    len_indent controls indentation of the ``len = ...`` assignment:
    callers at different nesting depths need different alignment.
    """
    emit(c_file, f'''
        if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
          {{
            size_t len = 0, i;
    ''', indent=1)
    emit_gen_key_with_check(c_file, obj.origname, indent=2)
    emit(c_file, f'''
        if (ptr != NULL && ptr->{obj.fixname} != NULL)
        {len_indent}len = ptr->{obj.fixname}_len;
    ''', indent=2)
    emit_beautify_off(c_file, '!len', indent=2)
    emit_gen_array_open(c_file, indent=2)
    check_gen_status(c_file, indent=2)


def emit_compound_gen(c_file, obj, key_name, gen_name, ptr_check='ptr != NULL', indent=1):
    """Emit generate code for a compound field (object, mapStringObject, basicMap)."""
    emit(c_file, f'''
        if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
          {{
    ''', indent=indent)
    emit_gen_key_with_check(c_file, key_name, indent=indent + 1)
    emit(c_file, f'''
            stat = gen_{gen_name} (g, {ptr_check} ? ptr->{obj.fixname} : NULL, ctx, err);
    ''', indent=indent + 1)
    check_gen_status(c_file, indent=indent + 1)
    emit(c_file, '''
          }
    ''', indent=indent)


def emit_pointer_clone(c_file, obj, sizeof_type, indent=1):
    """Emit clone code for a heap-allocated scalar (bool* or numeric*)."""
    emit(c_file, f'''
        if (src->{obj.fixname} != NULL)
          {{
            ret->{obj.fixname} = calloc (1, sizeof ({sizeof_type}));
            if (ret->{obj.fixname} == NULL)
                return NULL;
            *(ret->{obj.fixname}) = *(src->{obj.fixname});
          }}
    ''', indent=indent)


def get_compound_children(obj):
    """Get the children/subtypes for a compound type.

    Returns [] for mapStringObject, obj.children for object, obj.subtypobj for array.
    """
    return {'mapStringObject': [],
            'object': obj.children,
            'array': obj.subtypobj}[obj.typ]


# Type handler classes for C code generation
# Each type has methods for: parsing JSON, generating JSON, freeing memory, cloning

class TypeHandler:
    """Base class for type-specific C code generation."""

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        """Generate C code to parse this type from JSON."""
        pass

    def emit_generate(self, c_file, obj, prefix, indent=1):
        """Generate C code to serialize this type to JSON."""
        pass

    def emit_free(self, c_file, obj, prefix, indent=1):
        """Generate C code to free memory for this type."""
        pass

    def emit_clone(self, c_file, obj, prefix, indent=1):
        """Generate C code to clone/deep-copy this type."""
        pass

    def emit_read_value(self, c_file, src, dest, keyname, obj_typename, level=1):
        """Generate C code to read a value of this type."""
        pass

    def emit_json_value(self, c_file, src, dst, ptx, level=1):
        """Generate C code to write a JSON value of this type."""
        pass


class StringType(TypeHandler):
    """Handler for string type."""

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", {json_api.TYPE_STRING})',
                      f"ret->{obj.fixname}", 'string', obj.origname, obj_typename, indent=indent)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                char *str = "";
        ''', indent=indent)
        emit_gen_key_with_check(c_file, obj.origname, indent=indent + 1)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                    str = ptr->{obj.fixname};
        ''', indent=indent + 1)
        self.emit_json_value(c_file, "str", 'g', 'ctx', level=indent + 1)
        emit(c_file, '''
              }
        ''', indent=indent)

    def emit_free(self, c_file, obj, prefix, indent=1):
        free_and_null(c_file, "ptr", obj.fixname, indent=indent)

    def emit_clone(self, c_file, obj, prefix, indent=1):
        emit(c_file, f'''
            if (src->{obj.fixname} != NULL)
              {{
                ret->{obj.fixname} = strdup (src->{obj.fixname});
                if (ret->{obj.fixname} == NULL)
                  return NULL;
              }}
        ''', indent=indent)

    def emit_read_value(self, c_file, src, dest, keyname, obj_typename, level=1):
        emit(c_file, f'''
            {json_api.VAL_TYPE} val = {src};
            if (val != NULL)
              {{
                const char *str = {json_api.get_string('val')};
                {dest} = strdup (str ? str : "");
                if ({dest} == NULL)
                  return NULL;
              }}
        ''', indent=level)

    def emit_json_value(self, c_file, src, dst, ptx, level=1):
        emit(c_file, f'''
            stat = {json_api.gen_string(dst, src, f'strlen ({src})')};
            if (stat != {json_api.GEN_STATUS_OK})
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)


class BooleanType(TypeHandler):
    """Handler for boolean type."""

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", {json_api.TYPE_TRUE})',
                      f"ret->{obj.fixname}", 'boolean', obj.origname, obj_typename, indent=indent)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname}_present))
              {{
                bool b = false;
        ''', indent=indent)
        emit_gen_key_with_check(c_file, obj.origname, indent=indent + 1)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname})
                    b = ptr->{obj.fixname};

        ''', indent=indent + 1)
        self.emit_json_value(c_file, "b", 'g', 'ctx', level=indent + 1)
        emit(c_file, '''
              }
        ''', indent=indent)

    def emit_free(self, c_file, obj, prefix, indent=1):
        pass  # Boolean doesn't need freeing

    def emit_clone(self, c_file, obj, prefix, indent=1):
        emit(c_file, f'''
            ret->{obj.fixname} = src->{obj.fixname};
            ret->{obj.fixname}_present = src->{obj.fixname}_present;
        ''', indent=indent)

    def emit_read_value(self, c_file, src, dest, keyname, obj_typename, level=1):
        emit(c_file, f'''
            {json_api.VAL_TYPE} val = {src};
            if (val != NULL)
              {{
                {dest} = {json_api.is_true('val')};
        ''', indent=level)
        if '[' not in dest:
            emit(c_file, f'''
                    {dest}_present = 1;
              }}
            ''', indent=level + 1)
        else:
            emit(c_file, f'''
              }}
            ''', indent=level)

    def emit_json_value(self, c_file, src, dst, ptx, level=1):
        emit(c_file, f'''
            stat = {json_api.gen_bool(dst, src)};
            if (stat != {json_api.GEN_STATUS_OK})
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)


class BooleanPointerType(TypeHandler):
    """Handler for booleanPointer type."""

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", {json_api.TYPE_TRUE})',
                      f"ret->{obj.fixname}", 'booleanPointer', obj.origname, obj_typename, indent=indent)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        emit(c_file, f'''
            if ((ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                bool b = false;
        ''', indent=indent)
        emit_gen_key_with_check(c_file, obj.origname, indent=indent + 1)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                  {{
                    b = *(ptr->{obj.fixname});
                  }}
        ''', indent=indent + 1)
        self.emit_json_value(c_file, "b", 'g', 'ctx', level=indent + 1)
        emit(c_file, '''
              }
        ''', indent=indent)

    def emit_free(self, c_file, obj, prefix, indent=1):
        free_and_null(c_file, "ptr", obj.fixname, indent=indent)

    def emit_clone(self, c_file, obj, prefix, indent=1):
        emit_pointer_clone(c_file, obj, 'bool', indent=indent)

    def emit_read_value(self, c_file, src, dest, keyname, obj_typename, level=1):
        emit(c_file, f'''
            {json_api.VAL_TYPE} val = {src};
            if (val != NULL)
              {{
                {dest} = calloc (1, sizeof (bool));
                if ({dest} == NULL)
                    return NULL;
                *({dest}) = {json_api.is_true('val')};
              }}
        ''', indent=level)

    def emit_json_value(self, c_file, src, dst, ptx, level=1):
        emit(c_file, f'''
            stat = {json_api.gen_bool(dst, src)};
            if (stat != {json_api.GEN_STATUS_OK})
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)


class NumericType(TypeHandler):
    """Handler for numeric types (integer, double, int8-int64, uint8-uint64, UID, GID)."""

    def __init__(self, typ):
        self.typ = typ

    def _get_conversion_info(self):
        """Get conversion function and cast for this numeric type."""
        typ = self.typ
        if typ.startswith("uint") or (typ.startswith("int") and typ != "integer") or typ == "double":
            return f'common_safe_{typ}', '&'
        elif typ == "integer":
            return 'common_safe_int', '(int *)&'
        elif typ == "UID" or typ == "GID":
            return 'common_safe_uint', '(unsigned int *)&'
        return None, None

    def _get_c_numtype(self):
        """Get C type for JSON generation."""
        if self.typ == 'double':
            return 'double'
        elif self.typ.startswith("uint") or self.typ == 'GID' or self.typ == 'UID':
            return 'long long unsigned int'
        return 'long long int'

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", {json_api.TYPE_NUMBER})',
                      f"ret->{obj.fixname}", self.typ, obj.origname, obj_typename, indent=indent)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        numtyp = self._get_c_numtype()
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname}_present))
              {{
                {numtyp} num = 0;
        ''', indent=indent)
        emit_gen_key_with_check(c_file, obj.origname, indent=indent + 1)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname})
                    num = ({numtyp})ptr->{obj.fixname};
        ''', indent=indent + 1)
        self.emit_json_value(c_file, "num", 'g', 'ctx', level=indent + 1)
        emit(c_file, '''
              }
        ''', indent=indent)

    def emit_free(self, c_file, obj, prefix, indent=1):
        pass  # Numeric types don't need freeing

    def emit_clone(self, c_file, obj, prefix, indent=1):
        emit(c_file, f'''
            ret->{obj.fixname} = src->{obj.fixname};
            ret->{obj.fixname}_present = src->{obj.fixname}_present;
        ''', indent=indent)

    def emit_read_value(self, c_file, src, dest, keyname, obj_typename, level=1):
        conv_func, dest_cast = self._get_conversion_info()
        emit(c_file, f'''
            {json_api.VAL_TYPE} val = {src};
            if (val != NULL)
              {{
                int invalid;
        ''', indent=level)
        emit_invalid_type_check(c_file, json_api.is_number('val'), indent=level + 1)
        emit(c_file, f'''
                    invalid = {conv_func} ({json_api.get_number('val')}, {dest_cast}{dest});
                if (invalid)
                  {{
                    if (asprintf (err, "Invalid value '%s' with type '{self.typ}' for key '{keyname}': %s", {json_api.get_number('val')}, strerror (-invalid)) < 0)
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

    def emit_json_value(self, c_file, src, dst, ptx, level=1):
        if self.typ == 'double':
            emit(c_file, f'''
                stat = {json_api.gen_double(dst, src)};
            ''', indent=level)
        elif self.typ.startswith("uint") or self.typ == 'GID' or self.typ == 'UID':
            emit(c_file, f'''
                stat = map_uint ({dst}, {src});
            ''', indent=level)
        else:
            emit(c_file, f'''
                stat = map_int ({dst}, {src});
            ''', indent=level)
        emit(c_file, f'''
            if (stat != {json_api.GEN_STATUS_OK})
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)


class NumericPointerType(TypeHandler):
    """Handler for numeric pointer types (integerPointer, int8Pointer, etc.)."""

    def __init__(self, typ):
        self.typ = typ
        self.base_typ = helpers.get_pointer_base_type(typ)

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        do_read_value(c_file, f'get_val (tree, "{obj.origname}", {json_api.TYPE_NUMBER})',
                      f"ret->{obj.fixname}", self.typ, obj.origname, obj_typename, indent=indent)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        if self.base_typ == "":
            return
        emit(c_file, f'''
            if ((ptr != NULL && ptr->{obj.fixname} != NULL))
              {{
                {helpers.get_map_c_types(self.base_typ)} num = 0;
        ''', indent=indent)
        emit_gen_key_with_check(c_file, obj.origname, indent=indent + 1)
        emit(c_file, f'''
                if (ptr != NULL && ptr->{obj.fixname} != NULL)
                  {{
                    num = ({helpers.get_map_c_types(self.base_typ)})*(ptr->{obj.fixname});
                  }}
        ''', indent=indent + 1)
        NumericType(self.base_typ).emit_json_value(c_file, "num", 'g', 'ctx', level=indent + 1)
        emit(c_file, '''
              }
        ''', indent=indent)

    def emit_free(self, c_file, obj, prefix, indent=1):
        free_and_null(c_file, "ptr", obj.fixname, indent=indent)

    def emit_clone(self, c_file, obj, prefix, indent=1):
        emit_pointer_clone(c_file, obj, helpers.get_map_c_types(self.base_typ), indent=indent)

    def emit_read_value(self, c_file, src, dest, keyname, obj_typename, level=1):
        if self.base_typ == "":
            return
        emit(c_file, f'''
            {json_api.VAL_TYPE} val = {src};
            if (val != NULL)
              {{
                {dest} = calloc (1, sizeof ({helpers.get_map_c_types(self.base_typ)}));
                if ({dest} == NULL)
                    return NULL;
                int invalid;
        ''', indent=level)
        emit_invalid_type_check(c_file, json_api.is_number('val'), indent=level + 1)
        emit(c_file, f'''
                invalid = common_safe_{self.base_typ} ({json_api.get_number('val')}, {dest});
                if (invalid)
                  {{
                    if (asprintf (err, "Invalid value '%s' with type '{self.typ}' for key '{keyname}': %s", {json_api.get_number('val')}, strerror (-invalid)) < 0)
                        *err = strdup ("error allocating memory");
                    return NULL;
                  }}
              }}
        ''', indent=level)


class ObjectType(TypeHandler):
    """Handler for object type."""

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        typename = obj.subtypname or helpers.get_prefixed_name(obj.name, prefix)
        emit(c_file, f'''
            ret->{obj.fixname} = make_{typename} (get_val (tree, "{obj.origname}", {json_api.TYPE_OBJECT}), ctx, err);
            if (ret->{obj.fixname} == NULL && *err != 0)
              return NULL;
        ''', indent=indent)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        typename = obj.subtypname or helpers.get_prefixed_name(obj.name, prefix)
        emit_compound_gen(c_file, obj, obj.origname, typename, indent=indent)

    def emit_free(self, c_file, obj, prefix, indent=1):
        typename = obj.subtypname or helpers.get_prefixed_name(obj.name, prefix)
        emit(c_file, f'''
            if (ptr->{obj.fixname} != NULL)
              {{
                free_{typename} (ptr->{obj.fixname});
                ptr->{obj.fixname} = NULL;
              }}
        ''', indent=indent)

    def emit_clone(self, c_file, obj, prefix, indent=1):
        # Intentionally empty: object field cloning is handled explicitly in
        # emit_clone_body() because it requires typename resolution that the
        # simple handler dispatch pattern doesn't provide.
        pass

    def emit_make_body(self, c_file, obj, prefix):
        """Generate the body of make_typename() for objects."""
        obj_typename = helpers.get_prefixed_name(obj.name, prefix)
        nodes = obj.children
        required_to_check = []
        for i in nodes or []:
            if obj.required and i.origname in obj.required and \
                    not helpers.is_numeric_type(i.typ) and i.typ != 'boolean':
                required_to_check.append(i)
            handler = get_type_handler(i.typ)
            if handler:
                handler.emit_parse(c_file, i, prefix, obj_typename, indent=1)

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

        if obj.children is not None:
            condition = "\n                && ".join( \
                [f'strcmp (key_str, "{i.origname}")' for i in obj.children])
            emit(c_file, f'''
                if ({json_api.object_check('tree')})
                  {{
                    json_object *residual_obj = NULL;
                    size_t unknown_count = 0;

                    json_object_object_foreach (tree, key_str, key_val)
                      {{
                        (void) key_val;
                        if (key_str != NULL
                            && {condition})
                          {{
                            unknown_count++;
                            if (ctx->options & OPT_PARSE_FULLKEY)
                              {{
                                if (residual_obj == NULL)
                                  {{
                                    residual_obj = json_object_new_object ();
                                    if (residual_obj == NULL)
                                      return NULL;
                                  }}
                                json_object_object_add (residual_obj, key_str, json_object_get (key_val));
                              }}
                          }}
                      }}

                    if ((ctx->options & OPT_PARSE_STRICT) && unknown_count > 0 && ctx->errfile != NULL)
                      (void) fprintf (ctx->errfile, "WARNING: unknown key found\\n");

                    if ((ctx->options & OPT_PARSE_FULLKEY) && residual_obj != NULL)
                      ret->_residual = residual_obj;
                  }}
            ''', indent=1)

    def emit_gen_body(self, c_file, obj, prefix):
        """Generate the body of gen_typename() for objects."""
        nodes = obj.children
        if nodes is None:
            emit_beautify_off(c_file, 'true', indent=1)

        emit_gen_map_open(c_file, indent=1)
        check_gen_status(c_file, indent=1)
        for i in nodes or []:
            handler = get_type_handler(i.typ)
            if handler:
                handler.emit_generate(c_file, i, prefix, indent=1)
        if obj.children is not None:
            emit(c_file, f'''
                if (ptr != NULL && ptr->_residual != NULL)
                  {{
                    stat = {json_api.gen_residual('ptr->_residual', 'g', 'err')};
                    if ({json_api.GEN_STATUS_OK} != stat)
                        GEN_SET_ERROR_AND_RETURN (stat, err);
                  }}
            ''', indent=1)
        emit_gen_map_close(c_file, indent=1)
        check_gen_status(c_file, indent=1)
        if nodes is None:
            emit_beautify_on(c_file, 'true', indent=1)

    def emit_free_body(self, c_file, obj, prefix):
        """Generate the body of free_typename() for objects."""
        objs = obj.children
        for i in objs or []:
            handler = get_type_handler(i.typ)
            if handler:
                handler.emit_free(c_file, i, prefix, indent=1)

        if obj.children is not None:
            emit(c_file, f'''
                json_object_put (ptr->_residual);
                ptr->_residual = NULL;
            ''', indent=1)

    def emit_clone_body(self, c_file, obj, prefix):
        """Generate the body of clone_typename() for objects."""
        nodes = obj.children
        for i in nodes or []:
            handler = get_type_handler(i.typ)
            # Object type needs parent context (mapStringObject vs regular object)
            # so we handle it explicitly below rather than via handler
            if handler and i.typ != 'object':
                handler.emit_clone(c_file, i, prefix, indent=1)
            elif i.typ == 'object':
                node_name = i.subtypname or helpers.get_prefixed_name(i.name, prefix)
                emit(c_file, f'''
                    if (src->{i.fixname})
                      {{
                        ret->{i.fixname} = clone_{node_name} (src->{i.fixname});
                        if (ret->{i.fixname} == NULL)
                          return NULL;
                      }}
                ''', indent=1)
            else:
                raise Exception("Unimplemented type for clone: %s" % i.typ)


class MapStringObjectType(TypeHandler):
    """Handler for mapStringObject type."""

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        typename = obj.subtypname or helpers.get_prefixed_name(obj.name, prefix)
        emit(c_file, f'''
            ret->{obj.fixname} = make_{typename} (get_val (tree, "{obj.origname}", {json_api.TYPE_OBJECT}), ctx, err);
            if (ret->{obj.fixname} == NULL && *err != 0)
              return NULL;
        ''', indent=indent)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        typename = obj.subtypname or helpers.get_prefixed_name(obj.name, prefix)
        emit_compound_gen(c_file, obj, obj.origname, typename, indent=indent)

    def emit_free(self, c_file, obj, prefix, indent=1):
        free_func = obj.subtypname or helpers.get_prefixed_name(obj.name, prefix)
        emit(c_file, f'''
            free_{free_func} (ptr->{obj.fixname});
            ptr->{obj.fixname} = NULL;
        ''', indent=indent)

    def emit_clone(self, c_file, obj, prefix, indent=1):
        if obj.subtypname is not None:
            subtypname = obj.subtypname
            maybe_element = "_element"
        else:
            subtypname = obj.children[0].subtypname
            maybe_element = ""
        emit(c_file, f'''
            if (src->{obj.fixname})
              {{
                ret->{obj.fixname} = calloc (1, sizeof (*ret->{obj.fixname}));
                if (ret->{obj.fixname} == NULL)
                    return NULL;
                ret->{obj.fixname}->len = src->{obj.fixname}->len;
                ret->{obj.fixname}->keys = calloc (src->{obj.fixname}->len + 1, sizeof (char *));
                if (ret->{obj.fixname}->keys == NULL)
                    return NULL;
                ret->{obj.fixname}->values = calloc (src->{obj.fixname}->len + 1, sizeof (*ret->{obj.fixname}->values));
                if (ret->{obj.fixname}->values == NULL)
                    return NULL;
                for (size_t i = 0; i < ret->{obj.fixname}->len; i++)
                  {{
                    ret->{obj.fixname}->keys[i] = strdup (src->{obj.fixname}->keys[i]);
                    if (ret->{obj.fixname}->keys[i] == NULL)
                      return NULL;
                    ret->{obj.fixname}->values[i] = clone_{subtypname}{maybe_element} (src->{obj.fixname}->values[i]);
                    if (ret->{obj.fixname}->values[i] == NULL)
                      return NULL;
                  }}
              }}
        ''', indent=indent)

    def emit_make_body(self, c_file, obj, prefix):
        """Generate the body of make_typename() for mapStringObject."""
        child = obj.children[0]
        if helpers.valid_basic_map_name(child.typ):
            childname = helpers.make_basic_map_name(child.typ)
        else:
            if child.subtypname:
                childname = child.subtypname
            else:
                childname = helpers.get_prefixed_name(child.name, prefix)

        emit(c_file, f'''
            if ({json_api.object_check('tree')})
              {{
                size_t i;
                size_t len = {json_api.object_len('tree')};
                ret->len = len;
        ''', indent=1)

        calloc_with_check(c_file, 'ret->keys', 'len + 1', '*ret->keys', indent=2)
        calloc_with_check(c_file, f'ret->{child.fixname}', 'len + 1', f'*ret->{child.fixname}', indent=2)

        emit(c_file, f'''
                i = 0;
                json_object_object_foreach (tree, tmpkey, val)
                  {{
                    ret->keys[i] = strdup (tmpkey ? tmpkey : "");
        ''', indent=2)

        null_check_return(c_file, 'ret->keys[i]', indent=3)

        emit(c_file, f'''
                    ret->{child.fixname}[i] = make_{childname} (val, ctx, err);
        ''', indent=3)

        null_check_return(c_file, f'ret->{child.fixname}[i]', indent=3)

        c_file.append('                    i++;\n')
        c_file.append('      }\n')
        c_file.append('  }\n')

    def emit_gen_body(self, c_file, obj, prefix):
        """Generate the body of gen_typename() for mapStringObject."""
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
                    stat = {json_api.gen_string('g', 'str', 'strlen (str)')};
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

    def emit_free_body(self, c_file, obj, prefix):
        """Generate the body of free_typename() for mapStringObject."""
        child = obj.children[0]
        if helpers.valid_basic_map_name(child.typ):
            childname = helpers.make_basic_map_name(child.typ)
        else:
            if child.subtypname:
                childname = child.subtypname
            else:
                childname = helpers.get_prefixed_name(child.name, prefix)
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

    def emit_clone_body(self, c_file, obj, prefix):
        """Generate the body of clone_typename() for mapStringObject."""
        nodes = obj.children
        for i in nodes or []:
            handler = get_type_handler(i.typ)
            # Object type needs parent context for mapStringObject
            if handler and i.typ != 'object':
                handler.emit_clone(c_file, i, prefix, indent=1)
            elif i.typ == 'object':
                node_name = i.subtypname or helpers.get_prefixed_name(i.name, prefix)
                emit(c_file, f'''
                    if (src->{i.fixname})
                      {{
                        size_t i;
                        ret->len = src->len;
                        ret->keys = calloc (src->len + 1, sizeof (*ret->keys));
                        if (ret->keys == NULL)
                          return NULL;
                        for (i = 0; i < src->len; i++)
                          {{
                            ret->keys[i] = strdup (src->keys[i]);
                            if (ret->keys[i] == NULL)
                              return NULL;
                          }}
                        ret->{i.fixname} = calloc (src->len + 1, sizeof (*ret->{i.fixname}));
                        if (ret->{i.fixname} == NULL)
                          return NULL;
                        for (i = 0; i < src->len; i++)
                          {{
                             ret->{i.fixname}[i] = clone_{node_name} (src->{i.fixname}[i]);
                             if (ret->{i.fixname}[i] == NULL)
                               return NULL;
                          }}
                      }}
                ''', indent=1)
            else:
                raise Exception("Unimplemented type for clone: %s" % i.typ)


class BasicMapType(TypeHandler):
    """Handler for basic map types (mapStringString, mapStringInt, etc.)."""

    def __init__(self, typ):
        self.typ = typ
        self.map_name = helpers.make_basic_map_name(typ)

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        emit(c_file, f'''
            do
              {{
                {json_api.VAL_TYPE} tmp = get_val (tree, "{obj.origname}", {json_api.TYPE_OBJECT});
                if (tmp != NULL)
                  {{
                    ret->{obj.fixname} = make_{self.map_name} (tmp, ctx, err);
                    if (ret->{obj.fixname} == NULL)
                      {{
        ''', indent=indent)
        emit_value_error(c_file, obj.origname, indent=indent + 3)
        emit(c_file, '''
                  }
              }
          } while (0);
        ''', indent=indent)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        emit_compound_gen(c_file, obj, obj.fixname, self.map_name, ptr_check='ptr', indent=indent)

    def emit_free(self, c_file, obj, prefix, indent=1):
        emit(c_file, f'''
            free_{self.map_name} (ptr->{obj.fixname});
            ptr->{obj.fixname} = NULL;
        ''', indent=indent)

    def emit_read_value(self, c_file, src, dest, keyname, obj_typename, level=1):
        emit(c_file, f'''
            {json_api.VAL_TYPE} val = {src};
            if (val != NULL)
              {{
                {dest} = make_{self.map_name} (val, ctx, err);
                if ({dest} == NULL)
                  {{
        ''', indent=level)
        emit_value_error(c_file, keyname, indent=level + 2)
        emit(c_file, '''
                  }
              }
        ''', indent=level)

    def emit_json_value(self, c_file, src, dst, ptx, level=1):
        emit(c_file, f'''
            stat = gen_{self.map_name} ({dst}, {src}, {ptx}, err);
            if (stat != {json_api.GEN_STATUS_OK})
                GEN_SET_ERROR_AND_RETURN (stat, err);
        ''', indent=level)

    def emit_clone(self, c_file, obj, prefix, indent=1):
        # Clone function doesn't use json_ prefix
        clone_name = self.map_name.replace('json_', '', 1)
        emit(c_file, f'''
            if (src->{obj.fixname} != NULL)
              {{
                ret->{obj.fixname} = clone_{clone_name} (src->{obj.fixname});
                if (ret->{obj.fixname} == NULL)
                    return NULL;
              }}
        ''', indent=indent)


# Array subtype handlers for different element types
class ArraySubtypeHandler:
    """Base class for array subtype-specific code generation."""

    def emit_parse(self, c_file, obj, prefix, obj_typename):
        """Generate C code to parse array elements."""
        pass

    def emit_generate(self, c_file, obj, prefix):
        """Generate C code to serialize array elements."""
        pass

    def emit_free(self, c_file, obj, prefix):
        """Generate C code to free array elements."""
        pass

    def emit_clone(self, c_file, obj, prefix, indent):
        """Generate C code to clone array elements."""
        pass


class ObjectArrayHandler(ArraySubtypeHandler):
    """Handler for arrays of objects."""

    def emit_parse(self, c_file, obj, prefix, obj_typename):
        typename = obj.subtypname if obj.subtypname else helpers.get_name_substr(obj.name, prefix)

        emit_array_parse_preamble(c_file, obj)

        emit(c_file, f'''
                    for (i = 0; i < len; i++)
                      {{
                        {json_api.VAL_TYPE} val = {json_api.array_get('tmp', 'i')};
        ''', indent=3)

        if obj.nested_array:
            emit(c_file, f'''
                        size_t j;
                        ret->{obj.fixname}[i] = calloc ( {json_api.array_len('val')} + 1, sizeof (**ret->{obj.fixname}));
            ''', indent=4)
            null_check_return(c_file, f'ret->{obj.fixname}[i]', indent=4)
            emit(c_file, f'''
                        for (j = 0; j < {json_api.array_len('val')}; j++)
                          {{
            ''', indent=4)
            emit(c_file, f'''
                            ret->{obj.fixname}[i][j] = make_{typename} ({json_api.array_get('val', 'j')}, ctx, err);
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
              } while (0);
        ''', indent=1)

    def emit_generate(self, c_file, obj, prefix):
        typename = obj.subtypname if obj.subtypname else helpers.get_name_substr(obj.name, prefix)

        emit_array_gen_preamble(c_file, obj)

        emit(c_file, '''
                for (i = 0; i < len; i++)
                  {
        ''', indent=2)

        if obj.nested_array:
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

    def emit_free(self, c_file, obj, prefix):
        free_func = obj.subtypname if obj.subtypname is not None else helpers.get_name_substr(obj.name, prefix)

        emit(c_file, f'''
            if (ptr->{obj.fixname} != NULL)
              {{
                size_t i;
                for (i = 0; i < ptr->{obj.fixname}_len; i++)
                  {{
        ''', indent=1)

        if obj.nested_array:
            emit(c_file, f'''
                  size_t j;
                  for (j = 0; j < ptr->{obj.fixname}_item_lens[i]; j++)
                    {{
                      free_{free_func} (ptr->{obj.fixname}[i][j]);
                      ptr->{obj.fixname}[i][j] = NULL;
                  }}
            ''', indent=2)
            free_and_null(c_file, "ptr", f"{obj.fixname}[i]", indent=2)
        else:
            emit(c_file, f'''
                  if (ptr->{obj.fixname}[i] != NULL)
                    {{
                      free_{free_func} (ptr->{obj.fixname}[i]);
                      ptr->{obj.fixname}[i] = NULL;
                    }}
            ''', indent=2)

        emit(c_file, '''
                  }
        ''', indent=2)

        if obj.nested_array:
            free_and_null(c_file, "ptr", f"{obj.fixname}_item_lens", indent=2)

        free_and_null(c_file, "ptr", obj.fixname, indent=2)

        emit(c_file, '''
              }
        ''', indent=1)

    def emit_clone(self, c_file, obj, prefix, indent):
        typename = helpers.get_prefixed_name(obj.name, prefix)
        if obj.subtypname is not None:
            typename = obj.subtypname
        maybe_element = "_element" if obj.subtypname is None else ""

        if obj.nested_array:
            emit(c_file, f'''
                        ret->{obj.fixname}_item_lens[i] = src->{obj.fixname}_item_lens[i];
                        ret->{obj.fixname}[i] = calloc (ret->{obj.fixname}_item_lens[i] + 1, sizeof (**ret->{obj.fixname}[i]));
                        if (ret->{obj.fixname}[i] == NULL)
                            return NULL;
                        for (size_t j = 0; j < src->{obj.fixname}_item_lens[i]; j++)
                          {{
                            ret->{obj.fixname}[i][j] = clone_{typename}{maybe_element} (src->{obj.fixname}[i][j]);
                            if (ret->{obj.fixname}[i][j] == NULL)
                                return NULL;
                          }}
            ''', indent=indent+2)
        else:
            emit(c_file, f'''
                        ret->{obj.fixname}[i] = clone_{typename}{maybe_element} (src->{obj.fixname}[i]);
                        if (ret->{obj.fixname}[i] == NULL)
                            return NULL;
            ''', indent=indent+2)


class ByteArrayHandler(ArraySubtypeHandler):
    """Handler for byte arrays."""

    def emit_parse(self, c_file, obj, prefix, obj_typename):
        emit(c_file, f'''
            do
              {{
                {json_api.VAL_TYPE} tmp = get_val (tree, "{obj.origname}", {json_api.TYPE_STRING});
                if (tmp != NULL)
                  {{
        ''', indent=1)

        if obj.nested_array:
            emit(c_file, f'''
                    ret->{obj.fixname}_len = {json_api.array_len('tmp')};
                    ret->{obj.fixname} = calloc (ret->{obj.fixname}_len + 1, sizeof (*ret->{obj.fixname}));
            ''', indent=4)
            null_check_return(c_file, f'ret->{obj.fixname}', indent=4)
            emit(c_file, f'''
                    size_t j;
                    for (j = 0; j < ret->{obj.fixname}_len; j++)
                      {{
                        const char *str = {json_api.get_string(json_api.array_get('tmp', 'j'))};
            ''', indent=4)
            emit(c_file, f'''
                        ret->{obj.fixname}[j] = (uint8_t *)strdup (str ? str : "");
            ''', indent=5)
            null_check_return(c_file, f'ret->{obj.fixname}[j]', indent=5)
            emit(c_file, '''
                      }
            ''', indent=5)
        else:
            emit(c_file, f'''
                    const char *str = {json_api.get_string('tmp')};
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
              } while (0);
        ''', indent=1)

    def emit_generate(self, c_file, obj, prefix):
        emit(c_file, f'''
            if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->{obj.fixname} != NULL && ptr->{obj.fixname}_len))
              {{
                const char *str = "";
                size_t len = 0;
        ''', indent=1)
        emit_gen_key_with_check(c_file, obj.origname, indent=2)

        if obj.nested_array:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                {{
                    size_t i;
                    for (i = 0; i < ptr->{obj.fixname}_len; i++)
                      {{
                        if (ptr->{obj.fixname}[i] != NULL)
                            str = (const char *)ptr->{obj.fixname}[i];
                        else
                            str = "";
                        stat = {json_api.gen_string('g', 'str', 'strlen(str)')};
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
                stat = {json_api.gen_string('g', 'str', 'len')};
            ''', indent=2)

        check_gen_status(c_file, indent=2)

        emit(c_file, '''
              }
        ''', indent=1)

    def emit_free(self, c_file, obj, prefix):
        # Byte arrays use the primitive array free path
        pass

    def emit_clone(self, c_file, obj, prefix, indent):
        # Byte arrays use primitive clone (just copy)
        emit(c_file, f'''
                    ret->{obj.fixname}[i] = src->{obj.fixname}[i];
        ''', indent=indent+2)


class PrimitiveArrayHandler(ArraySubtypeHandler):
    """Handler for arrays of primitive types (string, numeric, etc.)."""

    def emit_parse(self, c_file, obj, prefix, obj_typename):
        emit_array_parse_preamble(c_file, obj)

        emit(c_file, '''
                    for (i = 0; i < len; i++)
                      {
        ''', indent=3)

        if obj.nested_array:
            emit(c_file, f'''
                        {json_api.VAL_TYPE} inner_arr = {json_api.array_get('tmp', 'i')};
                        ret->{obj.fixname}[i] = calloc ( {json_api.array_len('inner_arr')} + 1, sizeof (**ret->{obj.fixname}));
            ''', indent=4)
            null_check_return(c_file, f'ret->{obj.fixname}[i]', indent=5)
            emit(c_file, f'''
                        size_t j;
                        for (j = 0; j < {json_api.array_len('inner_arr')}; j++)
                          {{
            ''', indent=4)
            read_val_generator(c_file, 5, f'{json_api.array_get("inner_arr", "j")}',
                               f"ret->{obj.fixname}[i][j]", obj.subtyp, obj.origname, obj_typename)
            emit(c_file, f'''
                            ret->{obj.fixname}_item_lens[i] += 1;
                        }};
            ''', indent=5)
        else:
            read_val_generator(c_file, 4, f'{json_api.array_get("tmp", "i")}',
                               f"ret->{obj.fixname}[i]", obj.subtyp, obj.origname, obj_typename)

        emit(c_file, '''
                      }
                }
              } while (0);
        ''', indent=1)

    def emit_generate(self, c_file, obj, prefix):
        emit_array_gen_preamble(c_file, obj, len_indent='  ')

        emit(c_file, '''
                for (i = 0; i < len; i++)
                  {
        ''', indent=2)

        if obj.nested_array:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                    size_t j;
                    for (j = 0; j < ptr->{obj.fixname}_item_lens[i]; j++)
                      {{
            ''', indent=3)
            if obj.subtyp == 'string':
                emit(c_file, f'''
                        if (ptr->{obj.fixname}[i][j] == NULL)
                          continue;
                ''', indent=4)
            json_value_generator(c_file, 4, f"ptr->{obj.fixname}[i][j]", 'g', 'ctx', obj.subtyp)
            emit(c_file, '''
                      }
            ''', indent=4)
            emit_gen_array_close(c_file, indent=3)
        else:
            if obj.subtyp == 'string':
                emit(c_file, f'''
                    if (ptr->{obj.fixname}[i] == NULL)
                      continue;
                ''', indent=3)
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

    def emit_free(self, c_file, obj, prefix):
        if obj.subtyp == 'string':
            self._emit_free_string(c_file, obj)
        else:
            self._emit_free_numeric(c_file, obj)

    def _emit_free_string(self, c_file, obj):
        emit(c_file, f'''
            if (ptr->{obj.fixname} != NULL)
              {{
                size_t i;
                for (i = 0; i < ptr->{obj.fixname}_len; i++)
                  {{
        ''', indent=1)

        if obj.nested_array:
            emit(c_file, f'''
                    size_t j;
                    for (j = 0; j < ptr->{obj.fixname}_item_lens[i]; j++)
                      {{
            ''', indent=3)
            free_and_null(c_file, "ptr", f"{obj.fixname}[i][j]", indent=4)
            emit(c_file, '''
                      }
            ''', indent=3)

        emit(c_file, f'''
                    if (ptr->{obj.fixname}[i] != NULL)
                      {{
        ''', indent=3)

        free_and_null(c_file, "ptr", f"{obj.fixname}[i]", indent=4)

        emit(c_file, '''
                      }
                  }
        ''', indent=3)

        if obj.nested_array:
            free_and_null(c_file, "ptr", f"{obj.fixname}_item_lens", indent=2)

        free_and_null(c_file, "ptr", obj.fixname, indent=2)

        emit(c_file, '''
              }
        ''', indent=1)

    def _emit_free_numeric(self, c_file, obj):
        emit(c_file, '''
           {
        ''', indent=0)
        if obj.nested_array:
            emit(c_file, f'''
                    size_t i;
                    for (i = 0; i < ptr->{obj.fixname}_len; i++)
                      {{
            ''', indent=3)
            free_and_null(c_file, "ptr", f"{obj.fixname}[i]", indent=4)
            emit(c_file, '''
                      }
            ''', indent=3)
            free_and_null(c_file, "ptr", f"{obj.fixname}_item_lens", indent=3)
        free_and_null(c_file, "ptr", obj.fixname, indent=2)
        emit(c_file, '''
            }
        ''', indent=1)

    def emit_clone(self, c_file, obj, prefix, indent):
        if obj.subtyp == 'string':
            self._emit_clone_string(c_file, obj, indent)
        else:
            # Numeric types - simple copy
            emit(c_file, f'''
                    ret->{obj.fixname}[i] = src->{obj.fixname}[i];
            ''', indent=indent+2)

    def _emit_clone_string(self, c_file, obj, indent):
        if obj.nested_array:
            emit(c_file, f'''
                        ret->{obj.fixname}[i] = calloc (ret->{obj.fixname}_item_lens[i] + 1, sizeof (**ret->{obj.fixname}[i]));
                        if (ret->{obj.fixname}[i] == NULL)
                            return NULL;
                        for (size_t j = 0; j < src->{obj.fixname}_item_lens[i]; j++)
                          {{
                            ret->{obj.fixname}[i][j] = strdup (src->{obj.fixname}[i][j]);
                            if (ret->{obj.fixname}[i][j] == NULL)
                                return NULL;
                          }}
            ''', indent=indent+2)
        else:
            emit(c_file, f'''
                        if (src->{obj.fixname}[i])
                          {{
                            ret->{obj.fixname}[i] = strdup (src->{obj.fixname}[i]);
                            if (ret->{obj.fixname}[i] == NULL)
                                return NULL;
                          }}
            ''', indent=indent+2)


class BasicMapArrayHandler(ArraySubtypeHandler):
    """Handler for arrays of basic map types."""

    def emit_parse(self, c_file, obj, prefix, obj_typename):
        map_func = helpers.make_basic_map_name(obj.subtyp)
        emit_array_parse_preamble(c_file, obj)
        emit(c_file, f'''
                    for (i = 0; i < len; i++)
                      {{
                        {json_api.VAL_TYPE} val = {json_api.array_get('tmp', 'i')};
                        ret->{obj.fixname}[i] = make_{map_func} (val, ctx, err);
                        if (ret->{obj.fixname}[i] == NULL)
                          return NULL;
                      }}
                  }}
              }} while (0);
        ''', indent=1)

    def emit_generate(self, c_file, obj, prefix):
        map_func = helpers.make_basic_map_name(obj.subtyp)
        emit_array_gen_preamble(c_file, obj)
        emit(c_file, f'''
                for (i = 0; i < len; i++)
                  {{
                    stat = gen_{map_func} (g, ptr->{obj.fixname}[i], ctx, err);
                    if (stat != {json_api.GEN_STATUS_OK})
                        GEN_SET_ERROR_AND_RETURN (stat, err);
                  }}
        ''', indent=2)
        emit_gen_array_close(c_file, indent=2)
        emit_beautify_on(c_file, '!len', indent=2)
        emit(c_file, '''
              }
        ''', indent=1)

    def emit_free(self, c_file, obj, prefix):
        free_func = helpers.make_basic_map_name(obj.subtyp)
        emit(c_file, f'''
            if (ptr->{obj.fixname} != NULL)
              {{
                size_t i;
                for (i = 0; i < ptr->{obj.fixname}_len; i++)
                  {{
                    if (ptr->{obj.fixname}[i] != NULL)
                      {{
                        free_{free_func} (ptr->{obj.fixname}[i]);
                        ptr->{obj.fixname}[i] = NULL;
                      }}
                  }}
        ''', indent=1)
        free_and_null(c_file, "ptr", obj.fixname, indent=2)
        emit(c_file, '''
              }
        ''', indent=1)

    def emit_clone(self, c_file, obj, prefix, indent):
        # Clone function doesn't use json_ prefix
        clone_func = helpers.make_basic_map_name(obj.subtyp).replace('json_', '', 1)
        emit(c_file, f'''
            if (src->{obj.fixname}[i] != NULL)
              {{
                ret->{obj.fixname}[i] = clone_{clone_func} (src->{obj.fixname}[i]);
                if (ret->{obj.fixname}[i] == NULL)
                  return NULL;
              }}
        ''', indent=indent)


def _get_array_subtype_handler(obj):
    """Get the appropriate handler for an array's element type."""
    if helpers.valid_basic_map_name(obj.subtyp):
        return BasicMapArrayHandler()
    elif obj.subtypobj or obj.subtyp == 'object':
        return ObjectArrayHandler()
    elif obj.subtyp == 'byte':
        return ByteArrayHandler()
    else:
        return PrimitiveArrayHandler()


class ArrayType(TypeHandler):
    """Handler for array type.

    Delegates to specialized ArraySubtypeHandler classes based on element type.
    """

    def emit_parse(self, c_file, obj, prefix, obj_typename, indent=1):
        """Generate C code to parse an array from JSON."""
        handler = _get_array_subtype_handler(obj)
        handler.emit_parse(c_file, obj, prefix, obj_typename)

    def emit_generate(self, c_file, obj, prefix, indent=1):
        """Generate C code to serialize an array to JSON."""
        handler = _get_array_subtype_handler(obj)
        handler.emit_generate(c_file, obj, prefix)

    def emit_free(self, c_file, obj, prefix, indent=1):
        """Generate C code to free an array."""
        handler = _get_array_subtype_handler(obj)
        handler.emit_free(c_file, obj, prefix)

        # Handle additional cleanup for some array types
        c_typ = helpers.obtain_pointer(obj.name, obj.subtypobj, prefix)
        if c_typ == "":
            return
        if obj.subtypname is not None:
            c_typ = c_typ + "_element"

        emit(c_file, f'''
            free_{c_typ} (ptr->{obj.fixname});
            ptr->{obj.fixname} = NULL;
        ''', indent=1)

    def emit_clone(self, c_file, obj, prefix, indent=1):
        """Generate clone code for array fields."""
        emit(c_file, f'''
            if (src->{obj.fixname})
              {{
                ret->{obj.fixname}_len = src->{obj.fixname}_len;
                ret->{obj.fixname} = calloc (src->{obj.fixname}_len + 1, sizeof (*ret->{obj.fixname}));
                if (ret->{obj.fixname} == NULL)
                  return NULL;
                for (size_t i = 0; i < src->{obj.fixname}_len; i++)
                  {{
        ''', indent=indent)

        handler = _get_array_subtype_handler(obj)
        if helpers.is_numeric_type(obj.subtyp) or obj.subtyp == 'boolean':
            emit(c_file, f'''
                    ret->{obj.fixname}[i] = src->{obj.fixname}[i];
            ''', indent=indent+2)
        else:
            handler.emit_clone(c_file, obj, prefix, indent)

        emit(c_file, f'''
                  }}
              }}
        ''', indent=indent+1)

    def emit_make_body(self, c_file, obj, prefix):
        """Generate the body of make_typename() for array subtypes (element structs)."""
        obj_typename = helpers.get_name_substr(obj.name, prefix)
        nodes = obj.subtypobj
        required_to_check = []
        for i in nodes or []:
            if obj.required and i.origname in obj.required and \
                    not helpers.is_numeric_type(i.typ) and i.typ != 'boolean':
                required_to_check.append(i)
            handler = get_type_handler(i.typ)
            if handler:
                handler.emit_parse(c_file, i, prefix, obj_typename, indent=1)

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

    def emit_gen_body(self, c_file, obj, prefix):
        """Generate the body of gen_typename() for array subtypes."""
        nodes = obj.subtypobj
        if nodes is None:
            emit_beautify_off(c_file, 'true', indent=1)

        emit_gen_map_open(c_file, indent=1)
        check_gen_status(c_file, indent=1)
        for i in nodes or []:
            handler = get_type_handler(i.typ)
            if handler:
                handler.emit_generate(c_file, i, prefix, indent=1)
        emit_gen_map_close(c_file, indent=1)
        check_gen_status(c_file, indent=1)
        if nodes is None:
            emit_beautify_on(c_file, 'true', indent=1)

    def emit_free_body(self, c_file, obj, prefix):
        """Generate the body of free_typename() for array subtypes."""
        objs = obj.subtypobj
        for i in objs or []:
            handler = get_type_handler(i.typ)
            if handler:
                handler.emit_free(c_file, i, prefix, indent=1)

    def emit_clone_body(self, c_file, obj, prefix):
        """Generate the body of clone_typename() for array subtypes."""
        nodes = obj.subtypobj
        for i in nodes or []:
            handler = get_type_handler(i.typ)
            # Object type needs parent context
            if handler and i.typ != 'object':
                handler.emit_clone(c_file, i, prefix, indent=1)
            elif i.typ == 'object':
                node_name = i.subtypname or helpers.get_prefixed_name(i.name, prefix)
                emit(c_file, f'''
                    if (src->{i.fixname})
                      {{
                        ret->{i.fixname} = clone_{node_name} (src->{i.fixname});
                        if (ret->{i.fixname} == NULL)
                          return NULL;
                      }}
                ''', indent=1)
            else:
                raise Exception("Unimplemented type for clone: %s" % i.typ)


# Type handler registry
_TYPE_HANDLERS = {
    'string': StringType(),
    'boolean': BooleanType(),
    'booleanPointer': BooleanPointerType(),
    'object': ObjectType(),
    'mapStringObject': MapStringObjectType(),
    'array': ArrayType(),
}

def get_type_handler(typ):
    """Get the appropriate TypeHandler for a given type.

    Args:
        typ: The type string (e.g., 'string', 'boolean', 'uint64')

    Returns:
        TypeHandler instance or None if no handler exists
    """
    if typ in _TYPE_HANDLERS:
        return _TYPE_HANDLERS[typ]
    if helpers.is_numeric_type(typ):
        return NumericType(typ)
    if helpers.is_numeric_pointer_type(typ):
        return NumericPointerType(typ)
    if helpers.valid_basic_map_name(typ):
        return BasicMapType(typ)
    return None


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
        typename = helpers.get_prefixed_name(obj.name, prefix)
    if obj.typ == 'array':
        typename = helpers.get_name_substr(obj.name, prefix)
        if obj.subtypobj is None or obj.subtypname:
            return
    emit(c_file, f'''
        define_cleaner_function ({typename} *, free_{typename})
    ''', indent=0)
    c_file.append("\n")
    emit(c_file, f'''
        {typename} *
        make_{typename} ({json_api.VAL_TYPE}tree, const struct parser_context *ctx, parser_error *err)
        {{
            __auto_cleanup (free_{typename}) {typename} *ret = NULL;
            *err = NULL;
            (void) ctx; /* Silence compiler warning.  */
            if (tree == NULL)
              return NULL;
            ret = calloc (1, sizeof (*ret));
            if (ret == NULL)
              return NULL;
    ''', indent=0)

    handler = get_type_handler(obj.typ)
    if handler and hasattr(handler, 'emit_make_body'):
        handler.emit_make_body(c_file, obj, prefix)

    c_file.append("  return move_ptr (ret);\n")
    c_file.append("}\n")
    c_file.append("\n")


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
        if obj.subtypobj is None:
            return
    emit(c_file, f'''
        {json_api.GEN_STATUS_TYPE}
        gen_{typename} ({json_api.GEN_TYPE} g, const {typename} *ptr, const struct parser_context *ctx, parser_error *err)
        {{
            {json_api.GEN_STATUS_TYPE} stat = {json_api.GEN_STATUS_OK};
            *err = NULL;
            (void) ptr; /* Silence compiler warning.  */
    ''', indent=0)

    handler = get_type_handler(obj.typ)
    if handler and hasattr(handler, 'emit_gen_body'):
        handler.emit_gen_body(c_file, obj, prefix)

    c_file.append(f"  return {json_api.GEN_STATUS_OK};\n")
    c_file.append("}\n")
    c_file.append("\n")


def read_val_generator(c_file, level, src, dest, typ, keyname, obj_typename):
    """Generate C code to read a JSON value into a C variable."""
    handler = get_type_handler(typ)
    if handler:
        handler.emit_read_value(c_file, src, dest, keyname, obj_typename, level=level)


def make_clone(obj, c_file, prefix):
    """
    Description: generate a clone operation for the specified object
    Interface: None
    History: 2024-09-03
    """

    if not helpers.is_compound_type(obj.typ) or obj.subtypname:
        return
    typename = helpers.get_prefixed_name(obj.name, prefix)
    objs = get_compound_children(obj)
    if obj.typ == 'array':
        if objs is None:
            return
        typename = helpers.get_name_substr(obj.name, prefix)

    emit(c_file, f'''
        {typename} *
        clone_{typename} ({typename} *src)
        {{
            __auto_cleanup (free_{typename}) {typename} *ret = NULL;

            if (src == NULL)
              return NULL;

            ret = calloc (1, sizeof (*ret));
            if (ret == NULL)
              return NULL;
    ''', indent=0)

    handler = get_type_handler(obj.typ)
    if handler and hasattr(handler, 'emit_clone_body'):
        handler.emit_clone_body(c_file, obj, prefix)

    c_file.append("  return move_ptr (ret);\n")
    c_file.append("}\n")
    c_file.append("\n")


def json_value_generator(c_file, level, src, dst, ptx, typ):
    """Generate C code to write a JSON value."""
    handler = get_type_handler(typ)
    if handler:
        handler.emit_json_value(c_file, src, dst, ptx, level=level)


def make_c_free (obj, c_file, prefix):
    """
    Description: generate c free function
    Interface: None
    History: 2019-06-17
    """
    if not helpers.is_compound_type(obj.typ) or obj.subtypname:
        return
    typename = helpers.get_prefixed_name(obj.name, prefix)
    objs = get_compound_children(obj)
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

    handler = get_type_handler(obj.typ)
    if handler and hasattr(handler, 'emit_free_body'):
        handler.emit_free_body(c_file, obj, prefix)

    emit(c_file, '''
        free (ptr);
    ''', indent=1)
    c_file.append("}\n")


def src_reflect(structs, schema_info, c_file, root_typ):
    """
    Description: reflect code
    Interface: None
    History: 2019-06-17
    """
    emit(c_file, f'''
        /* Generated from {schema_info.name.basename}. Do not edit!  */

        #ifndef _GNU_SOURCE
        #  define _GNU_SOURCE
        #endif
        #include <string.h>
        #include "ocispec/{schema_info.header.basename}"
    ''', indent=0)
    for define in json_api.get_prologue_defines():
        c_file.append(define)
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
    ''', indent=0)
    c_file.append("\n")
    emit(c_file, f'''
        {typename}
        *make_{typename} ({json_api.VAL_TYPE}tree, const struct parser_context *ctx, parser_error *err)
        {{
            __auto_cleanup (free_{typename}) {typename} *ptr = NULL;
            size_t i, alen;

            (void) ctx;

            if (tree == NULL || err == NULL || ! ({json_api.array_check('tree')}))
              return NULL;
            *err = NULL;
            alen = {json_api.array_len('tree')};
            if (alen == 0)
              return NULL;
            ptr = calloc (1, sizeof ({typename}));
            if (ptr == NULL)
              return NULL;
            ptr->items = calloc (alen + 1, sizeof (*ptr->items));
            if (ptr->items == NULL)
              return NULL;
            ptr->len = alen;
    ''', indent=0)

    if obj.nested_array:
        emit(c_file, '''
            ptr->subitem_lens = calloc ( alen + 1, sizeof (size_t));
            if (ptr->subitem_lens == NULL)
              return NULL;
        ''', indent=1)

    emit(c_file, f'''

            for (i = 0; i < alen; i++)
              {{
                {json_api.VAL_TYPE} work = {json_api.array_get('tree', 'i')};
    ''', indent=1)

    if obj.subtypobj or obj.subtyp == 'object':
        if obj.subtypname:
            subtypename = obj.subtypname
        else:
            subtypename = helpers.get_name_substr(obj.name, prefix)

        if obj.nested_array:
            emit(c_file, f'''
                        size_t j;
                        ptr->items[i] = calloc ( {json_api.array_len('work')} + 1, sizeof (**ptr->items));
                        if (ptr->items[i] == NULL)
                          return NULL;
                        for (j = 0; j < {json_api.array_len('work')}; j++)
                          {{
                              ptr->items[i][j] = make_{subtypename} ({json_api.array_get('work', 'j')}, ctx, err);
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
        if obj.nested_array:
            emit(c_file, f'''
                        const char *str = {json_api.get_string('work')};
                        ptr->items[j] = (uint8_t *)strdup (str ? str : "");
                        if (ptr->items[j] == NULL)
                          return NULL;
            ''', indent=2)
        else:
            emit(c_file, f'''
                        const char *str = {json_api.get_string('tree')};
                        memcpy(ptr->items, str ? str : "", strlen(str ? str : ""));
                        break;
            ''', indent=2)
    else:
        if obj.nested_array:
            emit(c_file, f'''
                        ptr->items[i] = calloc ( {json_api.array_len('work')} + 1, sizeof (**ptr->items));
                        if (ptr->items[i] == NULL)
                          return NULL;
                        size_t j;
                        for (j = 0; j < {json_api.array_len('work')}; j++)
                          {{
            ''', indent=2)
            read_val_generator(c_file, 3, f'{json_api.array_get("work", "j")}', \
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
    c_file.append("  return move_ptr (ptr);\n")
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
        if obj.nested_array:
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
        if obj.nested_array:
            emit(c_file, '''
                        free (ptr->items[i]);
                        ptr->items[i] = NULL;
            ''', indent=2)
    elif obj.subtyp == 'object' or obj.subtypobj is not None:
        if obj.subtypname is not None:
            free_func = obj.subtypname
        else:
            free_func = helpers.get_name_substr(obj.name, prefix)

        if obj.nested_array:
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
    if obj.nested_array:
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
        {json_api.GEN_STATUS_TYPE} gen_{typename} ({json_api.GEN_TYPE} g, const {typename} *ptr, const struct parser_context *ctx,
                               parser_error *err)
        {{
            {json_api.GEN_STATUS_TYPE} stat;
            size_t i;

            if (ptr == NULL)
                return {json_api.GEN_STATUS_OK};
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
        if obj.nested_array:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                        size_t j;
                        for (j = 0; j < ptr->subitem_lens[i]; j++)
                          {{
                            stat = gen_{subtypename} (g, ptr->items[i][j], ctx, err);
                            if (stat != {json_api.GEN_STATUS_OK})
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
        if obj.nested_array:
            emit_gen_array_open(c_file, indent=3)
            check_gen_status(c_file, indent=3)
            emit(c_file, f'''
                        {{
                            size_t i;
                            for (i = 0; i < ptr->len; i++)
                              {{
                                if (ptr->items[i] != NULL)
                                    str = (const char *)ptr->items[i];
                                else
                                    str = "";
                                stat = {json_api.gen_string('g', 'str', 'strlen(str)')};
                              }}
                        }}
            ''', indent=3)
            emit_gen_array_close(c_file, indent=3)
        else:
            emit(c_file, f'''
                    if (ptr != NULL && ptr->items != NULL)
                      {{
                        str = (const char *)ptr->items;
                      }}
                    stat = {json_api.gen_string('g', 'str', 'ptr->len')};
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
        if obj.nested_array:
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


    emit(c_file, f'''

    if (ptr->len > 0 && !(ctx->options & OPT_GEN_SIMPLIFY))
        {json_api.gen_config('g', json_api.GEN_BEAUTIFY, '1')};
    if (stat != {json_api.GEN_STATUS_OK})
        GEN_SET_ERROR_AND_RETURN (stat, err);
    ''', indent=1)
    c_file.append(f"  return {json_api.GEN_STATUS_OK};\n")
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

        {json_api.get_val_cleaner_define()}
    ''', indent=0)
    c_file.append("\n")

    emit(c_file, f'''

        {typename} *
        {typename}_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)
        {{
            {typename} *ptr = NULL;
            __auto_cleanup ({json_api.DOC_FREE_FUNC}) {json_api.DOC_TYPE}tree = NULL;
            struct parser_context tmp_ctx = {{ 0 }};

            if (filename == NULL || err == NULL)
              return NULL;

            *err = NULL;
            if (ctx == NULL)
              ctx = (const struct parser_context *) (&tmp_ctx);

            tree = {json_api.doc_read_file('filename')};
            if (tree == NULL)
              {{
                if (asprintf (err, "cannot read the file: %s", filename) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
              }}
            ptr = make_{typename} (tree, ctx, err);
            return ptr;
        }}
    ''', indent=0)

    emit(c_file, f'''
        {typename} *
        {typename}_parse_file_stream (FILE *stream, const struct parser_context *ctx, parser_error *err)
        {{
            {typename} *ptr = NULL;
            __auto_cleanup ({json_api.DOC_FREE_FUNC}) {json_api.DOC_TYPE}tree = NULL;
            struct parser_context tmp_ctx = {{ 0 }};
            int fd;

            if (stream == NULL || err == NULL)
              return NULL;

            *err = NULL;
            if (ctx == NULL)
              ctx = (const struct parser_context *) (&tmp_ctx);

            fd = fileno (stream);
            if (fd >= 0)
              {{
                tree = {json_api.doc_read_fd('fd')};
              }}
            else
              {{
                __auto_free char *buf = NULL;
                size_t buf_len = 0, buf_alloc = 0;
                char tmp[4096];
                size_t nread;

                while ((nread = fread (tmp, 1, sizeof (tmp), stream)) > 0)
                  {{
                    if (buf_len + nread >= buf_alloc)
                      {{
                        char *newbuf;
                        buf_alloc = (buf_len + nread) * 2 + 1;
                        newbuf = realloc (buf, buf_alloc);
                        if (newbuf == NULL)
                          {{
                            *err = strdup ("error allocating memory");
                            return NULL;
                          }}
                        buf = newbuf;
                      }}
                    memcpy (buf + buf_len, tmp, nread);
                    buf_len += nread;
                  }}
                if (ferror (stream))
                  {{
                    *err = strdup ("error reading the file stream");
                    return NULL;
                  }}
                if (buf == NULL)
                  {{
                    *err = strdup ("cannot read the file stream");
                    return NULL;
                  }}
                buf[buf_len] = '\\0';
                tree = {json_api.doc_read('buf', 'buf_len')};
              }}
            if (tree == NULL)
              {{
                *err = strdup ("cannot read the file stream");
                return NULL;
              }}
            ptr = make_{typename} (tree, ctx, err);
            return ptr;
        }}
    ''', indent=0)

    emit(c_file, f'''
        {typename} *
        {typename}_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)
        {{
            {typename} *ptr = NULL;
            __auto_cleanup ({json_api.DOC_FREE_FUNC}) {json_api.DOC_TYPE}doc = NULL;
            {json_api.VAL_TYPE}tree = NULL;
            struct parser_context tmp_ctx = {{ 0 }};

            if (jsondata == NULL || err == NULL)
              return NULL;

            *err = NULL;
            if (ctx == NULL)
             ctx = (const struct parser_context *) (&tmp_ctx);

            doc = {json_api.doc_read('jsondata', 'strlen (jsondata)')};
            if (doc == NULL)
              {{
                *err = strdup ("cannot parse the data");
                return NULL;
              }}
            tree = {json_api.doc_get_root('doc')};
            if (tree == NULL)
              {{
                *err = strdup ("cannot parse the data");
                return NULL;
              }}
            ptr = make_{typename} (tree, ctx, err);
            return ptr;
        }}
    ''', indent=0)

    c_file.append(json_api.get_gen_cleanup_block())
    c_file.append("\n")

    emit(c_file, f'''
        char *
        {typename}_generate_json (const {typename} *ptr, const struct parser_context *ctx, parser_error *err)
        {{
            __auto_cleanup (cleanup_{json_api.GEN_TYPE_NAME}) {json_api.GEN_TYPE}g = NULL;
            struct parser_context tmp_ctx = {{ 0 }};
            const char *gen_buf = NULL;
            char *json_buf = NULL;
            size_t gen_len = 0;

            if (ptr == NULL || err == NULL)
              return NULL;

            *err = NULL;
            if (ctx == NULL)
                ctx = (const struct parser_context *) (&tmp_ctx);

            if (! json_gen_init (&g, ctx))
              {{
                *err = strdup ("Json_gen init failed");
                return json_buf;
              }}

            if ({json_api.GEN_STATUS_OK} != gen_{typename} (g, ptr, ctx, err))
              {{
                if (*err == NULL)
                    *err = strdup ("Failed to generate json");
                return json_buf;
              }}

            {json_api.gen_get_buf('g', '&gen_buf', '&gen_len')};
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
