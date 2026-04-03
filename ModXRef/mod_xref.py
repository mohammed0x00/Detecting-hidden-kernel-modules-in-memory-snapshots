'''
This module implements the ModXRef class,
which provides useful functions to detect rootkits implemented as LKMs
'''

# pylint: disable=no-else-return


from itertools import pairwise
import math
import struct
import logging

from typing import List, Iterable, Optional, Generator

from volatility3.framework import exceptions, renderers, constants, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces import plugins, layers
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux


vollog = logging.getLogger(__name__)



'''
According to the kernel docs, the number of params is unlimited, but the combined length is limited
For x86, this limit is 2048, for other architectures, it may vary
This constant is defined as COMMAND_LINE_SIZE
Doc about params: https://www.kernel.org/doc/html/v4.12/admin-guide/kernel-parameters.html
'''
MAX_MOD_PARAM_LEN = 2048


'''
Reasons why a kernel can be tainted, these apply to modules as well
See https://docs.kernel.org/admin-guide/tainted-kernels.html
'''
TAINT_REASONS = [
    'proprietary module was loaded',
    'module was force loaded',
    'kernel running on an out of specification system',
    'module was force unloaded',
    'processor reported a Machine Check Exception (MCE)',
    'bad page referenced or some unexpected page flags',
    'taint requested by userspace application',
    'kernel died recently, i.e. there was an OOPS or BUG',
    'ACPI table overridden by user',
    'kernel issued warning',
    'staging driver was loaded',
    'workaround for bug in platform firmware applied',
    'externally-built ("out-of-tree") module was loaded',
    'unsigned module was loaded',
    'soft lockup occurred',
    'kernel has been live patched',
    'auxiliary taint, defined for and used by distros',
    'kernel was built with the struct randomization plugin',
    'an in-kernel test has been run'
]


'''
Constants describing the state of modules
Based on enum module_state from include/linux/module.h
'''
MOD_STATE_MAP = {
    0: 'LIVE',
	1: 'LOADING',
	2: 'UNLOADING',
	3: 'UNFORMED'
}


'''
Binding and type constants from include/uapi/linux/elf.h
Used for parsing symbol table entries
'''
S_BIND = {
    0: 'LOCAL',
    1: 'GLOBAL',
    2: 'WEAK'
}

S_TYPE = {
    0: 'NOTYPE',
    1: 'OBJECT',
    2: 'FUNC',
    3: 'SECTION',
    4: 'FILE',
    5: 'COMMON',
    6: 'TLS'
}

VM_VM_AREA = 0x04
CACHE_LINE_ALIGNMENT = 64

'''
Module VMAs are stored in a well known memory range
https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
'''
MODULE_VMA_START = 0xffffffffa0000000
MODULE_VMA_END = 0xfffffffffeffffff



class ModXRef(plugins.PluginInterface):

    '''A class to enumerate Linux Kernel Modules from multiple sources'''

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._m_list = dict((m.vol.offset, m) for m in list(
            self.list_modules(self.context, self.config['kernel'])))
        self._m_kset = dict((m.vol.offset, m) for m in list(
            self.list_kset(self.context, self.config['kernel'])))

        try:

            self._m_tree = dict((m.vol.offset, m) for m in list(
                self.list_mod_trees(self.context, self.config['kernel'])))

        except exceptions.SymbolError as e:
            self._m_tree = {}
            vollog.debug(e)

        try:

            if self.config['vma']:
                self._m_vma_list, self._m_vma_tree = self.list_mods_from_vmas(
                    self.context, self.config['kernel'])
            else:
                self._m_vma_list = {}
                self._m_vma_tree = {}

        except exceptions.SymbolError as e:
            self._m_vma_list = {}
            self._m_vma_tree = {}
            vollog.debug(e)

        self._m_bug = dict((m.vol.offset, m) for m in list(
                self.list_bugs(self.context, self.config['kernel'])))

        self._m_ftrace = dict((m.vol.offset, m) for m in list(
                self.list_ftrace(self.context, self.config['kernel'])))

        self._m_all = {
            **self._m_list,
            **self._m_kset,
            **self._m_tree,
            **self._m_vma_list,
            **self._m_vma_tree,
            **self._m_bug,
            **self._m_ftrace
        }


    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name='kernel',
                description='Linux kernel',
                architectures=['Intel32', 'Intel64'],
            ),
            requirements.BooleanRequirement(
                name='taint-list',
                description=('Print taint value table, helps to interpret module taints'),
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name='dep-tree',
                description=('Draw dependency trees from the found modules'),
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name='dump',
                description=('Dump memory of selected modules'),
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name='syms',
                description=('Print symbols of the selected modules'),
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name='sects',
                description=('Print sections of the selected modules'),
                default=False,
                optional=True,
            ),
            requirements.ListRequirement(
                name='mods',
                description=('Restrict operations to specific modules,'
                             'identified by the offsets as hex values, separated with spaces'),
                element_type=str, # int cannot parse hex, manually converting to ints
                optional=True,
            ),
            requirements.BooleanRequirement(
                name='force',
                description=('Required in order to avoid accidentally dumping all module data'),
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name='vma',
                description=('Include virtual memory scanning while looking for modules '
                             '(warning: can be very slow, thus disabled by default)'),
                default=False,
                optional=True,
            ),
        ]



    @classmethod
    def list_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''A function to iterate through the linked list of modules'''

        vmlinux = context.modules[vmlinux_module_name]
        modules = vmlinux.object_from_symbol(symbol_name='modules').cast('list_head')
        table_name = modules.vol.type_name.split(constants.BANG)[0]

        yield from modules.to_list(table_name + constants.BANG + 'module', 'list')


    @classmethod
    def list_kset(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''A function to iterate through the kset which stores all modules'''

        vmlinux = context.modules[vmlinux_module_name]
        module_kset = vmlinux.object_from_symbol(symbol_name='module_kset')
        table_name = module_kset.vol.type_name.split(constants.BANG)[0]

        for kobj in module_kset.list.to_list(table_name + constants.BANG + 'kobject', 'entry'):

            mkobj = linux.LinuxUtilities.container_of(
                kobj.vol.offset, 'module_kobject', 'kobj', vmlinux
            ).cast('module_kobject')

            # TODO: on 3.2.0-4, mkobj.mod fails for some unknown reason
            # print(mkobj.has_member('mod'))
            if mkobj.mod == 0x0:
                continue

            yield context.object(
                    mkobj.vol.type_name.split(constants.BANG)[0] + constants.BANG + "module",
                    layer_name=vmlinux.layer_name, offset=mkobj.mod)


    @classmethod
    def list_mod_tree(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str, i: int
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''
        A function to traverse the latch red-black tree
        which is used to quickly access module layout information
        '''

        vmlinux = context.modules[vmlinux_module_name]
        mod_tree = vmlinux.object_from_symbol(symbol_name='mod_tree')

        for rb_node in traverse_rb_tree(mod_tree.root.tree[i].rb_node):

            latch_tree_node = indexable_container_of(
                rb_node, 'latch_tree_node', f'node[{i}]', vmlinux
            ).cast('latch_tree_node')

            mod_tree_node = linux.LinuxUtilities\
                .container_of(latch_tree_node.vol.offset, 'mod_tree_node', 'node', vmlinux)\
                .cast('mod_tree_node')

            yield context.object(
                    mod_tree_node.vol.type_name.split(constants.BANG)[0] +
                        constants.BANG + "module",
                    layer_name=vmlinux.layer_name, offset=mod_tree_node.mod)


    @classmethod
    def list_mod_trees(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''
        A wrapper function around list_mod_tree, checks if the tree exists
        and consistent, and returns one set of modules
        '''

        vmlinux = context.modules[vmlinux_module_name]
        if (vmlinux.has_type('module_layout') and vmlinux.get_type('module_layout').has_member('mtn')) \
        or (vmlinux.has_type('module_memory') and vmlinux.get_type('module_memory').has_member('mtn')):

            tree1 = dict((m.vol.offset, m) for m in list(
                cls.list_mod_tree(context, vmlinux_module_name, 0)))
            tree2 = dict((m.vol.offset, m) for m in list(
                cls.list_mod_tree(context, vmlinux_module_name, 1)))

            if sorted(tree1.keys()) != sorted(tree2.keys()):
                vollog.warning('The latch rb tree of the module layouts is incosistent')

                for i in tree1:
                    print(hex(i), tree1[i].get_name())

                for i in tree2:
                    print(hex(i), tree2[i].get_name())

            return tree1.values()

        else:
            return []


    @classmethod
    def list_vma_list(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''A function to iterate through the vmap_areas stored in vmap_area_list'''

        vmlinux = context.modules[vmlinux_module_name]

        if vmlinux.has_symbol('vmap_area_list'):

            vmap_area_list = vmlinux.object_from_symbol(symbol_name='vmap_area_list').cast('list_head')
            table_name = vmap_area_list.vol.type_name.split(constants.BANG)[0]

            yield from vmap_area_list.to_list(table_name + constants.BANG + 'vmap_area', 'list')

        elif vmlinux.has_symbol('vmap_nodes'):
            vmap_nodes = vmlinux.object_from_symbol(symbol_name='vmap_nodes')
            nr_vmap_nodes = vmlinux.object_from_symbol(symbol_name='nr_vmap_nodes')
            table_name = vmap_nodes.vol.type_name.split(constants.BANG)[0]

            for i in range(nr_vmap_nodes):

                type_dec = vmlinux.get_type('vmap_node')
                off = vmap_nodes + (type_dec.size * i)
                vmap = vmlinux.object(object_type='vmap_node', offset=off, absolute=True)

                yield from vmap.busy.head.to_list(table_name + constants.BANG + 'vmap_area', 'list')
                yield from vmap.lazy.head.to_list(table_name + constants.BANG + 'vmap_area', 'list')

            # table_name = vmap_area_list.vol.type_name.split(constants.BANG)[0]

            # yield from vmap_area_list.to_list(table_name + constants.BANG + 'vmap_area', 'list')

    @classmethod
    def list_vma_tree(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''A function to iterate through the vmap_areas stored in vmap_area_root'''

        vmlinux = context.modules[vmlinux_module_name]

        if vmlinux.has_symbol('vmap_area_root'):

            vmap_area_root = vmlinux.object_from_symbol(symbol_name='vmap_area_root')

            for rb_node in traverse_rb_tree(vmap_area_root.rb_node):

                yield linux.LinuxUtilities\
                    .container_of(rb_node, 'vmap_area', 'rb_node', vmlinux)\
                    .cast('vmap_area')

        elif vmlinux.has_symbol('vmap_nodes'):
            vmap_nodes = vmlinux.object_from_symbol(symbol_name='vmap_nodes')
            nr_vmap_nodes = vmlinux.object_from_symbol(symbol_name='nr_vmap_nodes')

            for i in range(nr_vmap_nodes):

                type_dec = vmlinux.get_type('vmap_node')
                off = vmap_nodes + (type_dec.size * i)
                vmap = vmlinux.object(object_type='vmap_node', offset=off, absolute=True)

                if vmap.busy.root.rb_node:
                    for rb_node in traverse_rb_tree(vmap.busy.root.rb_node):
                        yield linux.LinuxUtilities\
                            .container_of(rb_node, 'vmap_area', 'rb_node', vmlinux)\
                            .cast('vmap_area')

                if vmap.lazy.root.rb_node:
                    for rb_node in traverse_rb_tree(vmap.lazy.root.rb_node):
                        yield linux.LinuxUtilities\
                            .container_of(rb_node, 'vmap_area', 'rb_node', vmlinux)\
                            .cast('vmap_area')


    @classmethod
    def list_mods_from_vmas(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''A function to iterate through the kset which stores all modules'''

        vmlinux = context.modules[vmlinux_module_name]


        vma_list = dict((v.vol.offset, v) for v in list(
            cls.list_vma_list(context, vmlinux_module_name)))
        vma_tree = dict((v.vol.offset, v) for v in list(
            cls.list_vma_tree(context, vmlinux_module_name)))


        if sorted(vma_list.keys()) != sorted(vma_tree.keys()):
            vollog.warning('The vma rb tree and list are incosistent')

        # print(vma_list.keys())
        # print(vma_tree.keys())

        if vmlinux.has_symbol("mod_tree"):
            # Kernel >= 5.19    58d208de3e8d87dbe196caf0b57cc58c7a3836ca
            mod_tree = vmlinux.object_from_symbol("mod_tree")
            modules_addr_max = mod_tree.addr_max
        elif vmlinux.has_symbol("module_addr_min"):
            # 2.6.27 <= kernel < 5.19   3a642e99babe0617febb6f402e1e063479f489db
            modules_addr_max = vmlinux.object_from_symbol("module_addr_max")

        modules_addr_max = (modules_addr_max & 0x0000ffffffffffff)

        # print(hex(modules_addr_max))


        vmas = { **vma_list, **vma_tree }

        m_vma_list = {}
        m_vma_tree = {}

        for v in vmas:

            vma = vmas[v]

            if MODULE_VMA_START <= vma.va_start <= MODULE_VMA_END:

                if vma.has_member('vm'):
                    vm = vma.vm
    
                elif vma.has_member('private'):
                    if vma.flags & VM_VM_AREA != 0:
                        vm = vma.private.cast('vm_struct')
                    else:
                        continue

                elif vma.has_member('__bindgen_anon_1'):
                    vm = vma.__bindgen_anon_1.vm

                else:
                    continue



                if vmlinux.get_type('module').has_member('core_layout'):

                    mod_layout_head =  struct.pack('<QI', vma.va_start, vm.size-0x1000)

                    gen = context.layers[vmlinux.layer_name].scan(
                        context, scanners.BytesScanner(mod_layout_head),
                        sections=[(vm.addr, vm.addr+vm.size-0x1000)]
                    )

                    try:
                        addr = next(gen)
                    except StopIteration:
                        continue

                    mod = linux.LinuxUtilities.container_of(
                        addr, 'module', 'core_layout', vmlinux
                    ).cast('module')


                elif vmlinux.get_type('module').has_member('mem'):

                    mod_mem_head =  struct.pack('<QI', vma.va_start, vm.size-0x1000)

                    gen = context.layers[vmlinux.layer_name].scan(
                        context, scanners.BytesScanner(mod_mem_head),
                        sections=[(vm.addr, vm.addr+vm.size-0x1000)]
                    )

                    l = list(gen)

                    try:
                        addr = list(filter(lambda x: x < modules_addr_max, l))[0]
                    except:
                        continue

                    mod_mem = vmlinux.object(object_type='module_memory', offset=addr, absolute=True)

                    if mod_mem.mtn.mod != 0x0:
                        mod = vmlinux.object(object_type='module', offset=mod_mem.mtn.mod, absolute=True)

                else:

                    if (vma.va_start & 0x0000ffffffffffff) > modules_addr_max:
                        continue

                    mod_layout_head =  struct.pack('<QQ', 0, vma.va_start)

                    gen = context.layers[vmlinux.layer_name].scan(
                        context, scanners.BytesScanner(mod_layout_head),
                        sections=[((vma.va_start & 0x0000ffffffffffff), (vma.va_end - vma.va_start))]
                    )

                    l = list(gen)

                    try:
                        addr = l[-1]
                    except:
                        continue

                    mod = linux.LinuxUtilities.container_of(
                        addr, 'module', 'module_init', vmlinux
                    ).cast('module')

                if v in vma_list:
                    m_vma_list[mod.vol.offset] = mod

                if v in vma_tree:
                    m_vma_tree[mod.vol.offset] = mod

        return m_vma_list, m_vma_tree


    @classmethod
    def list_bugs(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''A function to iterate through the vmap_areas stored in vmap_area_list'''

        vmlinux = context.modules[vmlinux_module_name]
        module_bug_list = vmlinux.object_from_symbol(symbol_name='module_bug_list').cast('list_head')
        table_name = module_bug_list.vol.type_name.split(constants.BANG)[0]

        yield from module_bug_list.to_list(table_name + constants.BANG + 'module', 'bug_list')


    @classmethod
    def list_ftrace(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:

        '''A function to iterate through the vmap_areas stored in vmap_area_list'''

        vmlinux = context.modules[vmlinux_module_name]

        if vmlinux.has_symbol('ftrace_mod_maps'):
            ftrace_mod_maps = vmlinux.object_from_symbol(symbol_name='ftrace_mod_maps').cast('list_head')
            table_name = ftrace_mod_maps.vol.type_name.split(constants.BANG)[0]

            for modmap in ftrace_mod_maps.to_list(table_name + constants.BANG + 'ftrace_mod_map', 'list'):
                yield context.object(
                    table_name + constants.BANG + "module",
                    layer_name=vmlinux.layer_name, offset=modmap.mod)
        else:
            return []


    def _taints_generator(self):

        '''A function to display information about taints'''

        for i, r in enumerate(TAINT_REASONS):
            yield 0, (i, format_hints.Hex(2**i), r)


    def _mod_generator(self, offsets: List[str]):

        '''The function used to display consistency info & other information about modules'''

        vmlinux = self.context.modules[self.config["kernel"]]

        if offsets:
            m_filter = map(lambda x: int(x, 16), offsets)
        else:
            m_filter = self._m_all.keys()


        for o in m_filter:

            try:
                m = self._m_all[o]
            except KeyError as e:
                vollog.error('Could not find a module at %s', hex(o))
                raise e


            vmas = [ o in self._m_vma_list, o in self._m_vma_tree ] if self.config['vma'] else []
            modtree = [ o in self._m_tree ] if (m.has_member('core_layout') or m.has_member('mem')) else []
            ftrace = [o in self._m_ftrace] if vmlinux.has_type('ftrace_mod_map') else []

            try:
                yield 0, (
                    format_hints.Hex(o),
                    o in self._m_list,
                    o in self._m_kset,
                    *modtree,
                    *vmas,
                    o in self._m_bug,
                    *ftrace,
                    # theoretically, a kernel could be configured to not support module unloading
                    m.exit != 0 if m.has_member('exit') else False,
                    format_hints.Hex(m.taints),
                    m.sig_ok == 1 if m.has_member('sig_ok') else False,
                    MOD_STATE_MAP.get(m.state, '???'),
                    len(list(m.source_list.to_list(m.vol.type_name, 'source_list'))) if m.has_member('source_list') else 0,
                    len(list(m.target_list.to_list(m.vol.type_name, 'target_list'))) if m.has_member('target_list') else 0,
                    utility.pointer_to_string(m.srcversion, 25) if m.srcversion else '',
                    m.get_name(),
                    utility.pointer_to_string(m.version, 25) if m.version else '',
                    utility.pointer_to_string(m.args, MAX_MOD_PARAM_LEN),
                )
            except:
                print(hex(o), m.get_name())


    def _dep_tree_generator(self, offsets: List[str]):

        '''A function to display the dependency forest of kernel modules'''

        if offsets:
            m_filter = map(lambda x: int(x, 16), offsets)
        else:
            # filter for those modules that are roots of dependency trees
            m_filter = map(lambda x: x.vol.offset, filter(
                lambda m: len(list(m.source_list.to_list(m.vol.type_name, 'source_list'))) == 0,
                self._m_all.values()
            ))


        for o in m_filter:
            try:
                m = self._m_all[o]
            except KeyError as e:
                vollog.error('Could not find a module at %s', hex(o))
                raise e

            yield from yield_dep_tree(0, m)


    def _dump(self, offsets: List[str]):

        # pylint: disable=abstract-class-instantiated

        '''A function to dump the memory pages of modules'''

        # file layout
        # ehdr + shdrs + shstrtab + sections + symbols
        # probably ehdr + sections + shstrtab + shdrs + symbols is easier to implement


        def get_ehdr(is_64bit, num_sects, sh_off):

            e_ident64   = b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            e_ident32   = b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"

            e_type      = b"\x01\x00" # relocateble
            e_machine   = b"\x3e\x00" if is_64bit else b"\x03\x00"
            e_version   = b"\x01\x00\x00\x00"
            e_entry     = b"\x00" * (8 if is_64bit else 4)
            e_phoff     = b"\x00" * (8 if is_64bit else 4)
            e_shoff     = struct.pack("<Q", sh_off) if is_64bit else struct.pack("<I", sh_off)
            e_flags     = b"\x00\x00\x00\x00"
            e_ehsize    = b"\x40\x00" if is_64bit else b"\x34\x00"
            e_phentsize = b"\x00\x00"
            e_phnum     = b"\x00\x00"
            e_shentsize = b"\x40\x00" if is_64bit else b"\x28\x00"
            # TODO:
            e_shnum     = struct.pack("<H", num_sects + 1) # this works as we stick the seciton we create at the end
            e_shstrndx  = struct.pack("<H", num_sects)

            header = (e_ident64 if is_64bit else e_ident32)
            header += e_type + e_machine + e_version + e_entry + e_phoff + e_shoff + e_flags
            header += e_ehsize + e_phentsize + e_phnum + e_shentsize + e_shnum + e_shstrndx

            return header

        def get_shdr(name, sh_name, addr, size, file_off, strtab_idx, is_64bit):


            int_sh_type = _calc_sect_type(name)

            sh_type       = struct.pack("<I", int_sh_type)
            sh_flags      = struct.pack("<Q", _calc_sect_flags(name)) if is_64bit else struct.pack("<I", _calc_sect_flags(name))
            sh_addr       = struct.pack("<Q", addr) if is_64bit else struct.pack("<I", addr)
            sh_offset     = struct.pack("<Q", file_off) if is_64bit else struct.pack("<I", file_off)
            sh_size       = struct.pack("<Q", size) if is_64bit else struct.pack("<I", size)
            sh_link       = struct.pack("<I", _calc_link(name, strtab_idx, int_sh_type))
            sh_info       = b"\x00" * 4 
            sh_addralign  = b"\x01\x00\x00\x00\x00\x00\x00\x00" if is_64bit else b"\x01\x00\x00\x00"
            sh_entsize    = struct.pack("<Q", _calc_entsize(name, int_sh_type, 64)) if is_64bit \
                            else struct.pack("<I", _calc_entsize(name, int_sh_type, 32))
    
            if is_64bit:
                data = sh_name + sh_type + sh_flags + sh_addr + sh_offset + sh_size
                data = data + sh_link + sh_info + sh_addralign + sh_entsize
        
                if len(data) != 64:
                    vollog.error("Broken section building! %d" % len(data))
            else:
                data = sh_name + sh_type + sh_flags + sh_addr + sh_offset + sh_size
                data = data + sh_link + sh_info + sh_addralign + sh_entsize
        
                if len(data) != 40:
                    vollog.error("Broken section building! %d" % len(data))

            return data



        vmlinux = self.context.modules[self.config["kernel"]]
        is_64bit = symbols.symbol_table_is_64bit(self.context, vmlinux.symbol_table_name)

        if offsets:
            m_filter = map(lambda x: int(x, 16), offsets)
        else:
            m_filter = self._m_all.keys()


        for o in m_filter:

            try:
                m = self._m_all[o]
            except KeyError as e:
                vollog.error('Could not find a module at %s', hex(o))
                raise e

            name = m.get_name()

            if m.sect_attrs != 0x0:

                sections = self.context.object(
                    m.vol.type_name.split(constants.BANG)[0] + constants.BANG + 'array',
                    layer_name=vmlinux.layer_name,
                    offset=m.sect_attrs.attrs.vol.offset,
                    subtype=self.context.symbol_space.get_type(
                    m.vol.type_name.split(constants.BANG)[0] +
                        constants.BANG + 'module_sect_attr'
                    ),
                    count=m.sect_attrs.nsections)

                mmaps = []
                if m.has_member('core_layout'):
                    if m.core_layout.base != 0x0:
                        mmaps.append((
                            m.core_layout.base,
                            m.core_layout.base+m.core_layout.size
                        ))
                    if m.init_layout.base != 0x0:
                        mmaps.append((
                            m.init_layout.base,
                            m.init_layout.base+m.init_layout.size
                        ))
                elif m.has_member('mem'):
                    for i in range(7):
                        if m.mem[i].base != 0x0:
                            mmaps.append((
                                m.mem[i].base,
                                m.mem[i].base+m.mem[i].size
                            ))
                elif m.has_member('module_core'):
                    if m.module_core != 0x0:
                        mmaps.append((
                            m.module_core,
                            m.module_core+m.core_size
                        ))
                    if m.module_init != 0x0:
                        mmaps.append((
                            m.module_init,
                            m.module_init+m.init_size
                        ))
                else:
                    vollog.error('Failed to determine memory maps of the module')

                if len(mmaps) == 0:
                    vollog.error('Failed to determine memory maps of the module')


                nsections = 1
                for m_l, m_h in mmaps:
                    for s1, s2 in pairwise(sorted(list(sections), key=lambda x: x.address)):
                        if m_l <= (s1.address & 0x0000ffffffffffff) < m_h :
                            nsections += 1

                nsections += 2


                len_ehdr = (64 if is_64bit else 40)
                shstrtab = b'\x00'

                shdr = b'\x00' * (64 if is_64bit else 52)
                sectiondata = b''

                i = 1
                sec_map = {}

                for m_l, m_h in mmaps:
                    for s1, s2 in pairwise(sorted(list(sections), key=lambda x: x.address)):
                        if m_l <= (s1.address & 0x0000ffffffffffff) < m_h :

                            addr = s1.address #& 0x0000ffffffffffff
                            size = s2.address - s1.address

                            if s1.has_member('battr'):
                                name = utility.pointer_to_string(s1.battr.attr.name, 30)
                            elif s1.has_member('mattr'):
                                name = utility.pointer_to_string(s1.name, 30)

                            shdr += get_shdr(name, struct.pack("<I", len(shstrtab)), addr, size, len(sectiondata)+len_ehdr, nsections, is_64bit)
                            shstrtab += name.encode('ascii') + b'\x00'

                            try:
                                sectiondata += self.context.layers.read(vmlinux.layer_name, addr, size)
                            except:
                                sectiondata += b'\x00'*size

                            sec_map[name] = (i, addr, size)
                            i += 1


                symtab = b''

                if m.has_member('symtab'):

                    strtab = m.strtab
                    symnum = m.num_symtab
                    syms = self.context.object(
                                m.vol.type_name.split(constants.BANG)[0] + constants.BANG + "array",
                                layer_name=vmlinux.layer_name,
                                offset=m.symtab,
                                subtype=self.context.symbol_space.get_type(
                                    m.vol.type_name.split(constants.BANG)[0] + constants.BANG + ("elf64_sym" if is_64bit else 'elf32_sym')
                                ),
                                count=m.num_symtab,
                            )

                elif m.has_member('core_kallsyms'):

                    strtab = m.core_kallsyms.strtab
                    symnum = m.core_kallsyms.num_symtab
                    syms = self.context.object(
                                m.vol.type_name.split(constants.BANG)[0] + constants.BANG + "array",
                                layer_name=vmlinux.layer_name,
                                offset=m.core_kallsyms.symtab,
                                subtype=self.context.symbol_space.get_type(
                                    m.vol.type_name.split(constants.BANG)[0] + constants.BANG + ("elf64_sym" if is_64bit else 'elf32_sym')
                                ),
                                count=m.core_kallsyms.num_symtab,
                            )

                for s in sorted(list(syms), key=lambda x: x.st_value):

                    sym = b''

                    found = False
                    if s.st_value != 0:
                        for i, addr, size in sec_map.values():
                            if addr <= s.st_value <= addr+size:
                                found = True
                                break

                    if found:
                        b = (1 << 4) & 0xf0
                        t = 2 & 0xf
                        st_info = (b | t) & 0xff

                        if is_64bit:

                            sym += struct.pack('<I', s.st_name)
                            sym += struct.pack('<B', st_info)
                            sym += struct.pack('<B', s.st_other)
                            sym += struct.pack('<H', i)
                            sym += struct.pack('<Q', s.st_value - addr if s.st_value != 0 else 0)
                            sym += struct.pack('<Q', s.st_size)

                        else:

                            sym += struct.pack('<I', s.st_name)
                            sym += struct.pack('<I', s.st_value - addr if s.st_value != 0 else 0)
                            sym += struct.pack('<I', s.st_size)
                            sym += struct.pack('<B', st_info)
                            sym += struct.pack('<B', s.st_other)
                            sym += struct.pack('<H', i)

                        symtab += sym

                last_sym = sorted(list(syms), key=lambda x: x.st_name, reverse=True)[0]
                s_name = self.context.layers.read(
                    vmlinux.layer_name, strtab + last_sym.st_name, 0xff
                ).split(b'\x00')[0].decode('ascii')

                # where the last name starts, + its length + closing null byte
                strtabsize = last_sym.st_name + len(s_name) + 1
                symsize = len(symtab)


                shdr += get_shdr('.symtab', struct.pack("<I", len(shstrtab)), 0, symsize, len(sectiondata)+len_ehdr, nsections-1, is_64bit)
                shstrtab += b'.symtab\x00'
                # sectiondata += self.context.layers.read(vmlinux.layer_name, symtab, symsize)
                sectiondata += symtab


                shdr += get_shdr('.strtab', struct.pack("<I", len(shstrtab)), 0, strtabsize, len(sectiondata)+len_ehdr, nsections, is_64bit)
                shstrtab += b'.strtab\x00'
                sectiondata += self.context.layers.read(vmlinux.layer_name, strtab, strtabsize)

                shdr += get_shdr('.shstrtab', struct.pack("<I", len(shstrtab)), 0, len(shstrtab)+len(b'.shstrtab\x00'), len(sectiondata)+len_ehdr, nsections, is_64bit)
                shstrtab += b'.shstrtab\x00'

                ehdr = get_ehdr(is_64bit, nsections, len_ehdr + len(sectiondata) + len(shstrtab))

                data = ehdr + sectiondata + shstrtab + shdr

                with self.open(f'{m.get_name()}-dump.ko') as f:
                    f.write(data)

            else:
                pass


    def _symbols_generator(self, offsets: List[str]):

        '''A function to list all the (available) symbols for a module'''

        vmlinux = self.context.modules[self.config["kernel"]]
        is_64bit = symbols.symbol_table_is_64bit(self.context, vmlinux.symbol_table_name)


        if offsets:
            m_filter = map(lambda x: int(x, 16), offsets)
        else:
            m_filter = self._m_all.keys()


        for o in m_filter:

            try:
                m = self._m_all[o]
            except KeyError as e:
                vollog.error('Could not find a module at %s', hex(o))
                raise e


            if m.has_member('symtab'):

                strtab = m.strtab
                syms = self.context.object(
                            m.vol.type_name.split(constants.BANG)[0] + constants.BANG + "array",
                            layer_name=vmlinux.layer_name,
                            offset=m.symtab,
                            subtype=self.context.symbol_space.get_type(
                                m.vol.type_name.split(constants.BANG)[0] + constants.BANG + ("elf64_sym" if is_64bit else 'elf32_sym')
                            ),
                            count=m.num_symtab,
                        )

            elif m.has_member('core_kallsyms'):
                strtab = m.core_kallsyms.strtab
                syms = self.context.object(
                            m.vol.type_name.split(constants.BANG)[0] + constants.BANG + "array",
                            layer_name=vmlinux.layer_name,
                            offset=m.core_kallsyms.symtab,
                            subtype=self.context.symbol_space.get_type(
                                m.vol.type_name.split(constants.BANG)[0] + constants.BANG + ("elf64_sym" if is_64bit else 'elf32_sym')
                            ),
                            count=m.core_kallsyms.num_symtab,
                        )

            for s in syms:

                if s.st_name == 0x0:
                    continue

                s_name = self.context.layers.read(
                    vmlinux.layer_name, strtab + s.st_name, 0xff
                ).split(b'\x00')[0].decode('ascii')

                s_bind = s.st_info >> 4
                s_type = s.st_info & 0xf

                yield (0, [
                    format_hints.Hex(o),
                    s_name,
                    format_hints.Hex(s.st_value),
                    format_hints.Hex(s.st_size),
                    S_BIND.get(s_bind, '???'),
                    S_TYPE.get(s_type, '???')
                ])


    def _sections_generator(self, offsets: List[str]):

        vmlinux = self.context.modules[self.config["kernel"]]


        if offsets:
            m_filter = map(lambda x: int(x, 16), offsets)
        else:
            m_filter = self._m_all.keys()


        for o in m_filter:

            try:
                m = self._m_all[o]
            except KeyError as e:
                vollog.error('Could not find a module at %s', hex(o))
                raise e

            if m.sect_attrs == 0x0:
                vollog.warning('Module %s (0x%x) has its section attributes pointer set to NULL', m.get_name(), o)

            else:

                sections = self.context.object(
                            m.vol.type_name.split(constants.BANG)[0] + constants.BANG + 'array',
                            layer_name=vmlinux.layer_name,
                            offset=m.sect_attrs.attrs.vol.offset,
                            subtype=self.context.symbol_space.get_type(
                                m.vol.type_name.split(constants.BANG)[0] +
                                    constants.BANG + 'module_sect_attr'
                            ),
                            count=m.sect_attrs.nsections,
                        )


                for s in sorted(list(sections), key=lambda x: x.address):

                    if s.has_member('battr'):
                        name = utility.pointer_to_string(s.battr.attr.name, 30)
                    elif s.has_member('mattr'):
                        name = utility.pointer_to_string(s.name, 30)


                    yield (0, [
                        format_hints.Hex(o),
                        format_hints.Hex(s.address),
                        name
                    ])



    def run(self):

        # pylint: disable=too-many-return-statements

        if self.config['taint-list']:
            return renderers.TreeGrid(
                [
                    ('Bit', int),
                    ('Number', format_hints.Hex),
                    ('Reason', str)
                ],
                self._taints_generator(),
            )

        elif self.config['dep-tree']:
            return renderers.TreeGrid(
                [
                    ('Module Name', str)
                ],
                self._dep_tree_generator(self.config['mods']),
            )

        elif self.config['dump']:

            cols = [
                    ('Module offset', format_hints.Hex),
                    ('Base address', format_hints.Hex),
                    ('Size', format_hints.Hex),
                    ('Module Name', str),
                ]

            if not self.config['mods'] and not self.config['force']:
                vollog.warning('No modules selected to dump!'
                        'Either specify modules via --mod, or add --force to dump all modules!')
                return renderers.TreeGrid(cols, ())

            else:
                return renderers.TreeGrid(cols, self._dump(self.config['mods']))

        elif self.config['syms']:
            return renderers.TreeGrid(
                [
                    ('Module offset', format_hints.Hex),
                    ('Symbol', str),
                    ('Value', format_hints.Hex),
                    ('Size', format_hints.Hex),
                    ('Bind', str),
                    ('Type', str),
                ],
                self._symbols_generator(self.config['mods']),
            )

        elif self.config['sects']:
            return renderers.TreeGrid(
                [
                    ('Module offset', format_hints.Hex),
                    ('Section base address', format_hints.Hex),
                    ('Section name', str),
                ],
                self._sections_generator(self.config['mods']),
            )

        else:

            vmlinux = self.context.modules[self.config['kernel']]

            has_tree = (vmlinux.has_type('module_layout') and vmlinux.get_type('module_layout').has_member('mtn')) \
            or (vmlinux.has_type('module_memory') and vmlinux.get_type('module_memory').has_member('mtn'))
            has_ftrace = vmlinux.has_type('ftrace_mod_map')

            vmas = [('VMList', bool),('VMTree', bool)] if self.config['vma'] else []
            modtree = [('Tree', bool)] if has_tree else []
            ftrace = [('Ftrace', bool)] if has_ftrace else []

            return renderers.TreeGrid(
                [
                    ('Module offset', format_hints.Hex),
                    ('List', bool),
                    ('Kset', bool),
                    *modtree,
                    *vmas,
                    ('Bug', bool),
                    *ftrace,
                    ('Exit', bool),
                    ('Taint', format_hints.Hex),
                    ('Signed', bool),
                    ('State', str),
                    ('Used by', int),
                    ('Uses', int),
                    ('Src Version hash', str),
                    ('Module Name', str),
                    ('Version', str),
                    ('Args', str),
                ],
                self._mod_generator(self.config['mods']),
            )






#########################
#                       #
#   UTILIY FUNCTIONS    #
#                       #
#########################


def traverse_rb_tree(rb_node):

    '''Helper function to traverse reb-black trees'''

    if rb_node.rb_left:
        yield from traverse_rb_tree(rb_node.rb_left)

    yield rb_node

    if rb_node.rb_right:
        yield from traverse_rb_tree(rb_node.rb_right)


def yield_dep_tree(i, m):

    '''A function to generate module dependency trees recursively'''

    yield (i, [m.get_name()])
    for c in m.target_list.to_list(
        m.vol.type_name.split(constants.BANG)[0] + constants.BANG + 'module_use',
        'target_list'):

        yield from yield_dep_tree(i+1, c.target)


# pylint: disable=inconsistent-return-statements
def indexable_container_of(
    addr: int,
    type_name: str,
    member_name: str,
    vmlinux: interfaces.context.ModuleInterface,
) -> Optional[interfaces.objects.ObjectInterface]:

    '''Regular container_of extended to allow indexing on member_name'''

    if not addr:
        return

    if '[' in member_name and ']' == member_name[-1]:
        index = int(member_name.split('[')[1][:-1])
        member_name = member_name.split('[')[0]
    else:
        index = 0

    type_dec = vmlinux.get_type(type_name)
    c_type_dec = type_dec.child_template(member_name)
    member_offset = type_dec.relative_child_offset(member_name)

    # c_type_dec.size is the size of the array
    # c_type_dec.size // c_type_dec.count is the size of one array element
    container_addr = addr - (member_offset +
                ((c_type_dec.size // c_type_dec.count) * index))
    return vmlinux.object(
        object_type=type_name, offset=container_addr, absolute=True
    )

def _calc_sect_type(name):
    type_map = {
        "SHT_NULL" : 0,
        "SHT_PROGBITS" : 1,
        "SHT_SYMTAB" : 2,
        "SHT_STRTAB" : 3,
        "SHT_RELA" : 4,
        "SHT_HASH" : 5,
        "SHT_DYNAMIC" : 6,
        "SHT_NOTE" : 7,
        "SHT_NOBITS" : 8,
        "SHT_REL" : 9,
        "SHT_SHLIB" : 10,
        "SHT_DYNSYM" : 11,
        "SHT_LOPROC" : 0x70000000,
        "SHT_HIPROC" : 0x7fffffff,
        "SHT_LOUSER" : 0x80000000,
        "SHT_HIUSER" : 0xffffffff
    }
    
    known_sections = {
        ".note.gnu.build-id" : "SHT_NOTE",
        ".text"              : "SHT_PROGBITS",
        ".rodata"            : "SHT_PROGBITS",
        ".modinfo"           : "SHT_PROGBITS",
        "__param"            : "SHT_PROGBITS",
        ".data"              : "SHT_PROGBITS",
        ".gnu.linkonce.this_module" : "SHT_PROGBITS",
        ".comment"                  : "SHT_PROGBITS",
        ".shstrtab"                 : "SHT_STRTAB",
        ".symtab"                   : "SHT_SYMTAB",
        ".strtab"                   : "SHT_STRTAB",
        } 

    if name in known_sections:
        sect_type_name = known_sections[name]
        sect_type_val  = type_map[sect_type_name]
    else:
        sect_type_val = 1 # SHT_PROGBITS
    
    if name.find(".rela.") != -1:
        sect_type_val = 4 # SHT_RELA

    return sect_type_val

# all sections from memory are allocated (SHF_ALLOC)
# special check certain other sections to try and ensure extra flags are added where needed
def _calc_sect_flags(name):
    flags = 2 # SHF_ALLOC
    
    if name == ".text":
        flags = flags | 4 # SHF_EXECINSTR
    
    elif name in [".data", ".bss"]:
        flags = flags | 1 # SHF_WRITE

    return flags

def _calc_link(name, strtab_idx, sect_type):
    # looking for RELA sections
    if name.find(".rela.") != -1: 
        lnk = strtab_idx

    elif sect_type == 2: # strtab
        lnk = strtab_idx

    elif name == '.symtab':
        lnk = strtab_idx

    else:
        lnk = 0

    return lnk

def _calc_entsize(name, sect_type, bits):
    # looking for RELA sections
    if name.find(".rela.") != -1: 
        info = 24

    elif sect_type == 2: # symtab
        if bits == 32:
            info = 16
        else:
            info = 24
    else:
        info = 0

    return info
