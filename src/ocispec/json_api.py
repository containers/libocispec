# -*- coding: utf-8 -*-
#
# libocispec - a C library for parsing OCI spec files.
#
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

"""
JSON library abstraction for C code generation.

All JSON library-specific C code fragments are centralized in this module.
To switch to a different JSON library, modify this module only -- the rest
of the generator uses these names and helpers exclusively.
"""

# ---------------------------------------------------------------------------
# C type names
# ---------------------------------------------------------------------------
VAL_TYPE = "yajl_val"
GEN_TYPE = "yajl_gen"
GEN_STATUS_TYPE = "yajl_gen_status"
GEN_STATUS_OK = "yajl_gen_status_ok"

# ---------------------------------------------------------------------------
# Type constants passed to get_val()
# ---------------------------------------------------------------------------
TYPE_STRING = "yajl_t_string"
TYPE_NUMBER = "yajl_t_number"
TYPE_OBJECT = "yajl_t_object"
TYPE_ARRAY = "yajl_t_array"
TYPE_TRUE = "yajl_t_true"
TYPE_FALSE = "yajl_t_false"

# ---------------------------------------------------------------------------
# Value extraction -- each returns a C expression string
# ---------------------------------------------------------------------------

def get_string(val):
    return f"YAJL_GET_STRING ({val})"

def get_number(val):
    return f"YAJL_GET_NUMBER ({val})"

def is_number(val):
    return f"YAJL_IS_NUMBER ({val})"

def is_true(val):
    return f"YAJL_IS_TRUE ({val})"

# ---------------------------------------------------------------------------
# Array access -- each returns a C expression string
# ---------------------------------------------------------------------------

def array_check(val):
    return f"YAJL_GET_ARRAY ({val}) != NULL"

def array_len(val):
    return f"YAJL_GET_ARRAY_NO_CHECK ({val})->len"

def array_get(val, idx):
    return f"YAJL_GET_ARRAY_NO_CHECK ({val})->values[{idx}]"

def array_values(val):
    return f"YAJL_GET_ARRAY_NO_CHECK ({val})->values"

# ---------------------------------------------------------------------------
# Object access -- each returns a C expression string
# ---------------------------------------------------------------------------

def object_check(val):
    return f"YAJL_GET_OBJECT ({val}) != NULL"

def object_len(val):
    return f"YAJL_GET_OBJECT_NO_CHECK ({val})->len"

def object_keys(val):
    return f"YAJL_GET_OBJECT_NO_CHECK ({val})->keys"

def object_values(val):
    return f"YAJL_GET_OBJECT_NO_CHECK ({val})->values"

# ---------------------------------------------------------------------------
# Internal structure access (for residual handling)
# ---------------------------------------------------------------------------

def object_type_field(var):
    return f"{var}->type"

def object_type_value():
    return TYPE_OBJECT

def set_object_type(var):
    return f"{var}->type = {TYPE_OBJECT}"

def object_keys_field(var):
    return f"{var}->u.object.keys"

def object_values_field(var):
    return f"{var}->u.object.values"

def alloc_object_keys(var, count):
    return f"{var}->u.object.keys = calloc ({count}, sizeof (const char *))"

def alloc_object_values(var, count):
    return f"{var}->u.object.values = calloc ({count}, sizeof ({VAL_TYPE}))"

def object_key_direct(var, idx):
    return f"{var}->u.object.keys[{idx}]"

def object_value_direct(var, idx):
    return f"{var}->u.object.values[{idx}]"

def object_len_field(var):
    return f"{var}->u.object.len"

# ---------------------------------------------------------------------------
# Generation -- each returns a C expression string
# ---------------------------------------------------------------------------

def gen_string(gen, str_expr, len_expr):
    return f"yajl_gen_string (({GEN_TYPE}) {gen}, (const unsigned char *)({str_expr}), {len_expr})"

def gen_bool(gen, val):
    return f"yajl_gen_bool (({GEN_TYPE}){gen}, (int)({val}))"

def gen_double(gen, val):
    return f"yajl_gen_double (({GEN_TYPE}){gen}, {val})"

def gen_map_open(gen):
    return f"yajl_gen_map_open (({GEN_TYPE}) {gen})"

def gen_map_close(gen):
    return f"yajl_gen_map_close (({GEN_TYPE}) {gen})"

def gen_array_open(gen):
    return f"yajl_gen_array_open (({GEN_TYPE}) {gen})"

def gen_array_close(gen):
    return f"yajl_gen_array_close (({GEN_TYPE}) {gen})"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GEN_BEAUTIFY = "yajl_gen_beautify"

def gen_config(gen, option, val):
    return f"yajl_gen_config ({gen}, {option}, {val})"

# ---------------------------------------------------------------------------
# Buffer access and cleanup
# ---------------------------------------------------------------------------

def gen_get_buf(gen, buf_var, len_var):
    return f"yajl_gen_get_buf ({gen}, {buf_var}, {len_var})"

def gen_clear(gen):
    return f"yajl_gen_clear ({gen})"

def gen_free(gen):
    return f"yajl_gen_free ({gen})"

# ---------------------------------------------------------------------------
# Parsing and lifecycle
# ---------------------------------------------------------------------------

def tree_parse(data, buf, size):
    return f"yajl_tree_parse ({data}, {buf}, {size})"

TREE_FREE_FUNC = "yajl_tree_free"

def tree_free(val):
    return f"{TREE_FREE_FUNC} ({val})"

# ---------------------------------------------------------------------------
# Residual serialization
# ---------------------------------------------------------------------------
GEN_RESIDUAL_FUNC = "gen_yajl_object_residual"

def gen_residual(obj, gen, err):
    return f"{GEN_RESIDUAL_FUNC} ({obj}, {gen}, {err})"

# ---------------------------------------------------------------------------
# Prologue defines needed at the top of each generated .c file
# ---------------------------------------------------------------------------

def get_prologue_defines():
    return [
        "#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)\n",
        "#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)\n",
    ]

# ---------------------------------------------------------------------------
# Cleanup helpers emitted once per generated .c file (epilog)
# ---------------------------------------------------------------------------

def get_gen_cleanup_block():
    """Return the static cleanup function for the JSON generator."""
    return f"""\
static void
cleanup_{GEN_TYPE} ({GEN_TYPE} g)
{{
    if (!g)
      return;
    {gen_clear('g')};
    {gen_free('g')};
}}

define_cleaner_function ({GEN_TYPE}, cleanup_{GEN_TYPE})
"""

def get_val_cleaner_define():
    """Return the cleaner macro for the JSON value tree."""
    return f"define_cleaner_function ({VAL_TYPE}, {TREE_FREE_FUNC})"
