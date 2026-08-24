# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compatibility imports for :mod:`drgn.helpers.linux.btf`."""

from drgn.helpers.linux.btf import (  # noqa: F401
    build_c_declaration_object_finder,
    load_builtin_btf,
)

__all__ = ("build_c_declaration_object_finder", "load_builtin_btf")
