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

Current backend: yyjson
"""

# ---------------------------------------------------------------------------
# C type names
# ---------------------------------------------------------------------------
VAL_TYPE = "yyjson_val *"
DOC_TYPE = "yyjson_doc *"
GEN_TYPE = "json_gen_ctx *"
GEN_TYPE_NAME = "json_gen_ctx"       # without pointer, for function names
GEN_STATUS_TYPE = "json_gen_status"
GEN_STATUS_OK = "json_gen_status_ok"
RESIDUAL_TYPE = "char *"

# ---------------------------------------------------------------------------
# Type constants passed to get_val()
# ---------------------------------------------------------------------------
TYPE_STRING = "YYJSON_TYPE_STR"
TYPE_NUMBER = "YYJSON_TYPE_RAW"
TYPE_OBJECT = "YYJSON_TYPE_OBJ"
TYPE_ARRAY = "YYJSON_TYPE_ARR"
TYPE_BOOL = "YYJSON_TYPE_BOOL"
TYPE_TRUE = TYPE_BOOL
TYPE_FALSE = TYPE_BOOL

# ---------------------------------------------------------------------------
# Value extraction -- each returns a C expression string
# ---------------------------------------------------------------------------

def get_string(val):
    return f"yyjson_get_str ({val})"

def get_number(val):
    return f"yyjson_get_raw ({val})"

def is_number(val):
    return f"yyjson_is_raw ({val})"

def is_true(val):
    return f"yyjson_get_bool ({val})"

# ---------------------------------------------------------------------------
# Array access -- each returns a C expression string
# ---------------------------------------------------------------------------

def array_check(val):
    return f"yyjson_is_arr ({val})"

def array_len(val):
    return f"yyjson_arr_size ({val})"

def array_get(val, idx):
    return f"yyjson_arr_get ({val}, {idx})"

# ---------------------------------------------------------------------------
# Object access -- each returns a C expression string
# ---------------------------------------------------------------------------

def object_check(val):
    return f"yyjson_is_obj ({val})"

def object_len(val):
    return f"yyjson_obj_size ({val})"

# ---------------------------------------------------------------------------
# Generation -- each returns a C expression string
# ---------------------------------------------------------------------------

def gen_string(gen, str_expr, len_expr):
    return f"json_gen_string ({gen}, (const char *) ({str_expr}), {len_expr})"

def gen_bool(gen, val):
    return f"json_gen_bool ({gen}, (int) ({val}))"

def gen_double(gen, val):
    return f"json_gen_double ({gen}, {val})"

def gen_map_open(gen):
    return f"json_gen_map_open ({gen})"

def gen_map_close(gen):
    return f"json_gen_map_close ({gen})"

def gen_array_open(gen):
    return f"json_gen_array_open ({gen})"

def gen_array_close(gen):
    return f"json_gen_array_close ({gen})"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GEN_BEAUTIFY = "json_gen_beautify"

def gen_config(gen, option, val):
    return f"json_gen_config ({gen}, {option}, {val})"

# ---------------------------------------------------------------------------
# Buffer access and cleanup
# ---------------------------------------------------------------------------

def gen_get_buf(gen, buf_var, len_var):
    return f"json_gen_get_buf ({gen}, {buf_var}, {len_var})"

def gen_free(gen):
    return f"json_gen_free ({gen})"

# ---------------------------------------------------------------------------
# Parsing and lifecycle
# ---------------------------------------------------------------------------

READ_FLAGS = "YYJSON_READ_NUMBER_AS_RAW"
DOC_FREE_FUNC = "yyjson_doc_free"
TREE_FREE_FUNC = DOC_FREE_FUNC

def doc_read(data, len_expr):
    return f"yyjson_read ({data}, {len_expr}, {READ_FLAGS})"

def doc_get_root(doc):
    return f"yyjson_doc_get_root ({doc})"

# ---------------------------------------------------------------------------
# Residual serialization
# ---------------------------------------------------------------------------
GEN_RESIDUAL_FUNC = "gen_json_object_residual"

def gen_residual(obj, gen, err):
    return f"{GEN_RESIDUAL_FUNC} ({obj}, {gen}, {err})"

# ---------------------------------------------------------------------------
# Prologue defines needed at the top of each generated .c file
# ---------------------------------------------------------------------------

def get_prologue_defines():
    return []

# ---------------------------------------------------------------------------
# Cleanup helpers emitted once per generated .c file (epilog)
# ---------------------------------------------------------------------------

def get_gen_cleanup_block():
    """Return the static cleanup function for the JSON generator."""
    return f"""\
static void
cleanup_{GEN_TYPE_NAME} ({GEN_TYPE}g)
{{
  if (! g)
    return;
  {gen_free('g')};
}}

define_cleaner_function ({GEN_TYPE}, cleanup_{GEN_TYPE_NAME})
"""

def get_val_cleaner_define():
    """Return the cleaner macro for the JSON document."""
    return f"define_cleaner_function ({DOC_TYPE}, {DOC_FREE_FUNC})"
