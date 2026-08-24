# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
BTF
---

The :mod:`drgn.helpers.linux.btf` module contains helpers for using the BPF
Type Format (BTF) embedded in or published by the Linux kernel when DWARF
debugging information is unavailable.
"""

import logging
import os
import re
import weakref
from typing import Callable, Dict, Optional, Union

from drgn import (
    FaultError,
    FindObjectFlags,
    Module,
    Object,
    Program,
    ProgramFlags,
    _with_libbpf,
)
from drgn.helpers.linux.kallsyms import load_module_kallsyms, load_vmlinux_kallsyms
from drgn.helpers.linux.list import list_for_each_entry

__all__ = ("build_c_declaration_object_finder", "load_builtin_btf")


logger = logging.getLogger("drgn")

_DEFAULT_DECLARATIONS = """
// Needed to discover loadable modules and their split BTF.
struct list_head modules, btf_modules;
// Common bootstrap objects used by kernel helpers and stack traces.
struct list_head slab_caches;
struct task_struct init_task;
struct pid_namespace init_pid_ns;
"""

# A Program owns a strong reference to registered Python finders. Keeping weak
# references here lets repeated calls update the existing declaration finder
# without leaking the Program.
_declaration_finders: "weakref.WeakValueDictionary[int, Callable[..., object]]" = (
    weakref.WeakValueDictionary()
)


def _parse_c_declarations(decls: str) -> Dict[str, str]:
    name_to_type: Dict[str, str] = {}
    single_decl = r"\*?\s*[a-zA-Z_]\w*(?:\s*\[\s*\d*\s*\])*\s*"
    declarator_list = re.compile(
        r"(?:" + single_decl + r",\s*)*" + single_decl + r";\s*$"
    )
    for decl in decls.strip().splitlines():
        comment_start = decl.find("//")
        if comment_start >= 0:
            decl = decl[:comment_start]
        decl = decl.strip()
        if not decl:
            continue
        match = declarator_list.search(decl)
        if not match:
            raise ValueError(f"Invalid declaration: {decl}")
        type_string = decl[: -len(match.group(0))]
        for name in match.group(0).rstrip(";").split(","):
            this_type = type_string
            name = name.strip()
            if name.startswith("*"):
                this_type += " *"
                name = name[1:].lstrip()
            start_bracket = name.find("[")
            if start_bracket > 0:
                this_type += " " + name[start_bracket:]
                name = name[:start_bracket]
            name_to_type[name.strip()] = this_type
    return name_to_type


def _unique_symbol_address(prog: Program, name: str) -> int:
    symbols = prog.symbols(name)
    try:
        ranges = prog.main_module().address_ranges
    except LookupError:
        ranges = None
    if ranges is not None:
        symbols = [
            symbol
            for symbol in symbols
            if any(start <= symbol.address < end for start, end in ranges)
        ]
    addresses = {symbol.address for symbol in symbols}
    if not addresses:
        raise LookupError(f"could not find symbol with name {name!r}")
    if len(addresses) > 1:
        raise LookupError(f"symbol {name!r} is ambiguous in the main kernel module")
    return addresses.pop()


def build_c_declaration_object_finder(
    decls: str,
) -> Callable[[Program, str, FindObjectFlags, Optional[str]], Optional[Object]]:
    """
    Create an object finder from C variable declarations.

    Most kernel BTF only maps per-CPU variable names to types. This helper
    combines caller-supplied C declarations with symbol addresses, which makes
    selected ordinary globals usable as drgn objects too. Declarations may
    contain variable declarations, ``//`` comments, and blank lines. Function
    and type declarations are not supported.

    :param decls: C-style variable declarations.
    :return: An object finder suitable for
        :meth:`drgn.Program.register_object_finder()`.
    """
    name_to_type = _parse_c_declarations(decls)

    def find_object(
        prog: Program, name: str, flags: FindObjectFlags, filename: Optional[str]
    ) -> Optional[Object]:
        # BTF and kallsyms don't contain source filename information.
        if (
            filename is None
            and flags & FindObjectFlags.VARIABLE
            and name in name_to_type
        ):
            return Object(
                prog,
                name_to_type[name],
                address=_unique_symbol_address(prog, name),
            )
        return None

    # load_builtin_btf() uses this to add or override declarations when called
    # repeatedly for the same Program.
    setattr(find_object, "_drgn_name_to_type", name_to_type)
    return find_object


def _enable_symbol_finder(prog: Program, name: str, finder: object, index: int) -> None:
    if name not in prog.registered_symbol_finders():
        prog.register_symbol_finder(name, finder)  # type: ignore[arg-type]
    enabled = prog.enabled_symbol_finders()
    if name not in enabled:
        enabled.insert(min(index, len(enabled)), name)
        prog.set_enabled_symbol_finders(enabled)


def _enable_kernel_object_finders(prog: Program, declarations: Optional[str]) -> None:
    registered = prog.registered_object_finders()
    if "btf_kernel" not in registered:
        raise NotImplementedError(
            "drgn was not built with kernel BTF object finder support"
        )

    finder = _declaration_finders.get(id(prog))
    if finder is None:
        if "btf_manual_globals" in registered:
            raise ValueError(
                "an unrelated object finder named 'btf_manual_globals' is already registered"
            )
        all_declarations = _DEFAULT_DECLARATIONS
        if declarations:
            all_declarations += "\n" + declarations
        finder = build_c_declaration_object_finder(all_declarations)
        _declaration_finders[id(prog)] = finder
        prog.register_object_finder("btf_manual_globals", finder)
    elif declarations:
        name_to_type = getattr(finder, "_drgn_name_to_type")
        name_to_type.update(_parse_c_declarations(declarations))

    enabled = prog.enabled_object_finders()
    for name in ("btf_kernel", "btf_manual_globals"):
        try:
            enabled.remove(name)
        except ValueError:
            pass
    try:
        index = enabled.index("btf")
    except ValueError:
        index = len(enabled)
    enabled[index:index] = ["btf_kernel", "btf_manual_globals"]
    prog.set_enabled_object_finders(enabled)


def _is_live_local_kernel(prog: Program) -> bool:
    return prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL) == (
        ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
    )


def _attach_elf_btf(kernel: Module, path: Union[str, bytes, os.PathLike]) -> bool:
    path = os.fspath(path)
    with open(path, "rb") as file:
        is_elf = file.read(4) == b"\x7fELF"
    if is_elf:
        kernel.try_file(path, force=True)
    return is_elf


def _load_vmlinux_btf(
    prog: Program,
    kernel: Module,
    path: Optional[Union[str, bytes, os.PathLike]],
    path_is_elf: bool,
) -> None:
    if path is not None:
        if path_is_elf:
            kernel.load_btf(main_module_base=False)
        else:
            with open(path, "rb") as file:
                kernel.load_btf(data=file.read(), main_module_base=False)
        return

    sysfs_path = "/sys/kernel/btf/vmlinux"
    if _is_live_local_kernel(prog) and os.path.isfile(sysfs_path):
        with open(sysfs_path, "rb") as file:
            kernel.load_btf(data=file.read(), main_module_base=False)
        return

    try:
        start = prog.symbol("__start_BTF").address
        stop = prog.symbol("__stop_BTF").address
    except LookupError:
        # A stripped vmlinux may still have been associated with the module.
        kernel.load_btf(main_module_base=False)
        return
    if stop <= start or stop - start > 0xFFFFFFFF:
        raise ValueError(f"invalid built-in BTF address range: {start:#x}-{stop:#x}")
    try:
        data = prog.read(start, stop - start)
        kernel.load_btf(data=data, main_module_base=False)
    except (FaultError, ValueError) as memory_error:
        try:
            kernel.load_btf(main_module_base=False)
        except Exception as elf_error:
            raise RuntimeError(
                "could not load built-in BTF from target memory "
                f"({memory_error}) or an associated ELF file ({elf_error}); "
                "supply an explicit raw BTF or vmlinux path"
            ) from memory_error


def _set_vmlinux_address_range(prog: Program, kernel: Module) -> None:
    if kernel.address_ranges is not None:
        return
    try:
        start = prog.symbol("_stext").address
        end = prog.symbol("_end").address
    except LookupError as error:
        logger.warning(
            "could not determine the vmlinux address range from _stext and _end; "
            "built-in ORC unwinding may be unavailable: %s",
            error,
        )
        return
    if end <= start:
        if _is_live_local_kernel(prog) and start == end == 0:
            raise PermissionError(
                "/proc/kallsyms returned zero addresses; run drgn as root and "
                "check kernel.kptr_restrict and kernel lockdown"
            )
        raise ValueError(f"invalid vmlinux address range: {start:#x}-{end:#x}")
    kernel.address_range = (start, end)


def _load_module_btf(prog: Program, use_sysfs: bool) -> None:
    module_btf: Dict[str, bytes] = {}
    if use_sysfs:
        for name in sorted(os.listdir("/sys/kernel/btf")):
            if name == "vmlinux":
                continue
            try:
                with open(os.path.join("/sys/kernel/btf", name), "rb") as file:
                    module_btf[name] = file.read()
            except FileNotFoundError:
                # Modules may be unloaded while the directory is traversed.
                continue
    else:
        try:
            btf_modules = prog["btf_modules"].address_of_()
        except LookupError:
            logger.info("kernel does not expose split module BTF")
            return
        btf_module_type = prog.type("struct btf_module")
        data_in_btf_module = btf_module_type.has_member("btf_data_size")
        for btf_module in list_for_each_entry(btf_module_type, btf_modules, "list"):
            name = btf_module.module.name.string_().decode()
            if data_in_btf_module:
                module_btf[name] = prog.read(
                    btf_module.btf, btf_module.btf_data_size.value_()
                )
            else:
                module_btf[name] = prog.read(
                    btf_module.btf.data, btf_module.btf.data_size.value_()
                )

    try:
        prog.create_loaded_modules()
    except (LookupError, ValueError) as error:
        logger.warning("could not enumerate kernel modules for BTF: %s", error)
        return
    for name, data in module_btf.items():
        try:
            prog.module(name).load_btf(data=data)
        except LookupError:
            # The module may have disappeared between the BTF and module walks.
            continue
        except ValueError as error:
            # Main vmlinux BTF remains useful if one split module is malformed
            # or races with unload.
            logger.warning("could not load BTF for module %s: %s", name, error)

    try:
        finder = load_module_kallsyms(prog)
    except (LookupError, ValueError) as error:
        logger.warning("could not load kernel module kallsyms: %s", error)
    else:
        _enable_symbol_finder(prog, "module_kallsyms", finder, 1)


def load_builtin_btf(
    prog: Program,
    declarations: Optional[str] = None,
    *,
    path: Optional[Union[str, bytes, os.PathLike]] = None,
    load_modules: bool = True,
) -> None:
    """
    Load kernel BTF and kallsyms as a DWARF-free debugging fallback.

    The main BTF is loaded from *path* when provided. The path may name raw BTF
    or an ELF file containing a ``.BTF`` section. Otherwise, this tries
    :file:`/sys/kernel/btf/vmlinux`, the target's ``__start_BTF`` and
    ``__stop_BTF`` symbols, and finally an ELF file already associated with the
    main module.

    Kallsyms supplies function and variable addresses. Kernel BTF ordinarily
    supplies types for only per-CPU variables, so a small set of declarations
    needed for module discovery and stack access is always installed. Caller
    *declarations* are additive and override defaults with the same name.

    Repeated calls are safe. Existing BTF and finder registrations are reused,
    and new declarations are added to the existing declaration finder.

    :param prog: Linux kernel program to configure.
    :param declarations: Additional C-style global variable declarations.
    :param path: Optional raw BTF or ELF file.
    :param load_modules: Also load split BTF and kallsyms for loadable modules.
    """
    if not prog.flags & ProgramFlags.IS_LINUX_KERNEL:
        raise ValueError("BTF kernel fallback requires a Linux kernel Program")
    if not _with_libbpf:
        raise NotImplementedError("drgn was not built with libbpf support")

    kernel = prog.main_module("kernel", create=True)
    path_is_elf = False
    if path is not None:
        # Attach an explicitly supplied ELF before looking up kallsyms so that
        # its ordinary symbol table can serve as a fallback.
        path_is_elf = _attach_elf_btf(kernel, path)

    if "vmlinux_kallsyms" not in prog.registered_symbol_finders():
        try:
            finder = load_vmlinux_kallsyms(prog)
        except Exception as error:
            # An explicitly supplied vmlinux, or one found by normal debug-info
            # discovery, may still provide everything kallsyms would provide.
            try:
                prog.symbol("_stext")
                prog.symbol("_end")
            except LookupError:
                if _is_live_local_kernel(prog):
                    raise PermissionError(
                        "could not load /proc/kallsyms; run drgn as root and "
                        "check kernel.kptr_restrict"
                    ) from error
                raise RuntimeError(
                    "could not load in-memory kallsyms; the vmcore needs Linux "
                    "6.0-era kallsyms VMCOREINFO metadata or an explicit vmlinux "
                    "symbol table"
                ) from error
            logger.warning(
                "could not load kallsyms; using the associated ELF symbol table: %s",
                error,
            )
        else:
            _enable_symbol_finder(prog, "vmlinux_kallsyms", finder, 0)
    else:
        _enable_symbol_finder(prog, "vmlinux_kallsyms", (), 0)

    _set_vmlinux_address_range(prog, kernel)
    _load_vmlinux_btf(prog, kernel, path, path_is_elf)

    _enable_kernel_object_finders(prog, declarations)

    if load_modules:
        use_sysfs = _is_live_local_kernel(prog) and os.path.isdir("/sys/kernel/btf")
        _load_module_btf(prog, use_sysfs)
