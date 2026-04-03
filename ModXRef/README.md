# ModXRef - Volatility3 plugin to find hidden Linux Kernel Modules

## Overview

This plugin performs cross-view-based detection of Loadable Kernel Modules, the de-facto delivery method of kernel rootkits. These rootkits often hide the modules that implement their functionality by removing them from certain kernel data structures. This plugin is capable of traversing 7 different data structures and compare their content to find inconsistencies, that were caused by hiding rootkits.

## Features

The plugin is capable of enumerating kernel modules from 7 different sources (2 of these are disabled by default due to performance reasons, they can be enabled via the `--vma` flag). It reports all modules it can find through these sources and for each of them, it is reported, in which data structures were they found. A set of useful information is also displayed for each of these modules, for example if they have an exit function, their taints, wether they are signed or not, their state, how many other modules depend on them, how many modules they depend on, their src version hash, name and arguments:


```
$ % vol -p ModXRef -s symtabs/ -f dumps/wild/brokepkg.ko.elf mod_xref  
Volatility 3 Framework 2.11.0
Progress:  100.00		PDB scanning finished                          
Module offset   List    Kset	Tree	Bug     Ftrace    Exit	Taint Signed  State	Used by	Uses	Src Version hash	Module Name	Version	Args

0xffffc08e3440	True	True	True	True	False	  True	0x0   True	  LIVE	0	      1		                    vboxsf		
0xffffc08dc500	True	True	True	True	False	  True	0x0	  True	  LIVE	0	      1		                    intel_rapl_msr		
0xffffc08ce400	True	True	True	True	False	  True	0x0	  True	  LIVE	1	      0		                    intel_rapl_common		
0xffffc079a0c0	True	True	True	True	False	  False	0x0	  True	  LIVE	0	      0		                    intel_uncore_frequency_common
```

In order to help deeper investigation of modules, the plugin is also capable of the followings:
- Display dependency trees, using certain modules as the root of these trees.
- Display symbols of certain modules.
- List sections of certain modules.
- Partially reconstruct certain modules from memory, i.e. dump the available sections into a `.ko` file. These `.ko` files can be analyzed by reverse engineering tools, like Ghidra or Radare2.

## Installation & usage

Just clone the repository and point Volatility's `-p` flag to the downloaded repository. Once it's done, Volatility should be able to find the plugin by the name `mod_xref`.

Alternatively, download only `mod_xref.py` and place it in a directory, where Volatility looks for plugins.



## Parameters

```
$ vol -p ModXRef mod_xref -h
Volatility 3 Framework 2.11.0
usage: volatility mod_xref.ModXRef [-h] [--taint-list] [--dep-tree] [--dump] [--syms] [--sects] [--mods [MODS ...]] [--force] [--vma]

A class to enumerate Linux Kernel Modules from multiple sources

options:
  -h, --help         show this help message and exit
  --taint-list       Print taint value table, helps to interpret module taints
  --dep-tree         Draw dependency trees from the found modules
  --dump             Dump memory of selected modules
  --syms             Print symbols of the selected modules
  --sects            Print sections of the selected modules
  --mods [MODS ...]  Restrict operations to specific modules,identified by the offsets as hex values, separated with spaces
  --force            Required in order to avoid accidentally dumping all module data
  --vma              Include virtual memory scanning while looking for modules (warning: can be very slow, thus disabled by default)
```


## Further information

A detailed description of how this plugin works can be found [here](https://www.crysys.hu/~rnagy/publications/files/Nagy2025DFRWSUS.pdf).


## Test data

The dataset, that was used to evaluate this plugin can be accessed [here](https://www.crysys.hu/~rnagy/datasets/rootkit.html).

## Citation

If you use either the Volatility plugin, or the dataset, please cite our paper:

```
@article{nagy2025hiddenlkm,
  title={Detecting Hidden Kernel Modules in Memory Snapshots},
  author={Nagy, Roland},
  journal={Forensic Science International: Digital Investigation},
  year={2025},
  publisher={Elsevier},
  note = {DFRWS USA 2025 - Selected Papers from the 25th Annual Digital Forensics Research Conference USA},
}
```