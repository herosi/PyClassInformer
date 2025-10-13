import ida_idaapi
import ida_funcs
import ida_name
import ida_bytes
import idautils

import pyclassinformer

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

tree_categorize = True
try:
    import ida_dirtree
    ida_dirtree.dirtree_t.find_entry
# For IDA 7.4 and 7.5
except ModuleNotFoundError:
    tree_categorize = False
# For IDA 7.6
except AttributeError:
    tree_categorize = False

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
ida_idaapi.require("pyclassinformer.pci_config")
if tree_categorize:
    ida_idaapi.require("pyclassinformer.mc_tree")
    ida_idaapi.require("pyclassinformer.dirtree_utils")

# lazy utils accessor to avoid construction when not available in tests
_u = None
def get_utils():
    global _u
    if _u is None:
        try:
            _u = pyclassinformer.pci_utils.utils()
        except Exception:
            _u = None
    return _u

def change_dir_of_ctors_dtors(paths, data, dirtree):
    path_prefix = "/classes/"
    
    # move virtual functions to its class folder
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        
        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        
        for refea in idautils.DataRefsTo(vftable_ea):
            f = ida_funcs.get_func(refea)
            if f:
                func_name = ida_funcs.get_func_name(f.start_ea)
                # make a directory with a class name
                dst_path = path_prefix + class_name + "/possible ctors or dtors/"
                dirtree.mkdir(dst_path)
                
                # if the vfunc is at the top level, move it into the vftables folder.
                func_path = "/" + func_name
            
                # get the func path in the dir tree.
                dirtree_path = pyclassinformer.dirtree_utils.get_abs_path_by_inode(dirtree, f.start_ea)
            
                # check if the function is at the top level or not.
                # and rename it.
                if func_path == dirtree_path:
                    #print(func_path)
                    dirtree.rename(func_path, dst_path)
        
def change_dir_of_vfuncs(paths, data, dirtree):
    path_prefix = "/classes/"
    
    # move virtual functions to its class folder
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        
        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        vfunc_eas = data[vftable_ea].vfeas
        #print(hex(vftable_ea), class_name, len(vfunc_eas), list(reversed([x.name for x in path])))
        
        # make a directory with a class name
        dst_path = path_prefix + class_name + "/virtual methods/"
        dirtree.mkdir(dst_path)
        
        # move virtual functions into the class name folder
        for vfea in vfunc_eas:
            func_name = ida_funcs.get_func_name(vfea)
            
            # sometimes, a function is not form of a function.
            # try to fix it or skip it
            if func_name is None:
                ida_funcs.add_func(vfea)
                f = ida_funcs.get_func(vfea)
                if f is None:
                    print("Warning: a virtual method at {:#x} in {} is not a function and failed to add it as a function. Skipping...".format(vfea, class_name))
                    continue
                
                # get func name again after creating a function
                func_name = ida_funcs.get_func_name(vfea)
                if func_name is None:
                    print("Warning: the func name of the virtual method at {:#x} in {} could not be obtaind. Skipping...".format(vfea, class_name))
                    continue
            #print(hex(vfea), func_name)
                
            # if the vfunc is at the top level, move it into the vftables folder.
            func_path = "/" + func_name
            
            # get the func path in the dir tree.
            dirtree_path = pyclassinformer.dirtree_utils.get_abs_path_by_inode(dirtree, vfea)
            
            # check if the function is at the top level or not.
            # and rename it.
            if func_path == dirtree_path:
                #print(func_path)
                dirtree.rename(func_path, dst_path)
                
        # just create directories for rest of classes
        for bcd in path[1:]:
            dst_path = path_prefix + bcd.name
            dirtree.mkdir(dst_path)


def rename_func(ea, prefix="", fn="", is_lib=False):
    func_name = ida_funcs.get_func_name(ea)
    
    # if a virtuame method is not a valid function, skip it
    if func_name is None:
        return False
    
    # rename the function name if it is a dummy name
    if func_name.startswith("sub_") or func_name.startswith("unknown_"):
        # change the function name to the specific name
        if fn:
            func_name = fn
        ida_name.set_name(ea, prefix + func_name, ida_name.SN_NOCHECK|ida_name.SN_FORCE)
        
    # add FUNC_LIB to make ida recognize the function as a part of static linked libraries
    if is_lib:
        f = ida_funcs.get_func(ea)
        if not f.flags & ida_funcs.FUNC_LIB:
            f.flags |= ida_funcs.FUNC_LIB
            ida_funcs.update_func(f)
    return True


def rename_vftable_ref_funcs(paths, data):
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]
        
        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        
        # check the class is a part of standard library classes such as STL and MFC
        is_lib = False
        if col.libflag == col.LIBLIB:
            is_lib = True
        
        # get the func eas that refer to vftables and rename them
        #print(hex(vftable_ea))
        for refea in idautils.DataRefsTo(vftable_ea):
            #print(hex(refea))
            f = ida_funcs.get_func(refea)
            if f:
                rename_func(f.start_ea, class_name.split("<")[0] + "::", "possible_ctor_or_dtor", is_lib=is_lib)


def rename_funcs(func_eas, prefix="", is_lib=False):
    for ea in func_eas:
        rename_func(ea, prefix, is_lib=is_lib)


def rename_vfuncs(paths, data):
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]
        
        # get the class name that owns the vftable, which is the last entry of the path.
        #print(hex(vftable_ea), path)
        class_name = path[-1].name
        vfunc_eas = data[vftable_ea].vfeas
        
        # check the class is a part of standard library classes such as STL and MFC
        is_lib = False
        if col.libflag == col.LIBLIB:
            is_lib = True
        
        rename_funcs(vfunc_eas, class_name.split("<")[0] + "::", is_lib=is_lib)


def add_vfunc_index_comments(paths, data):
    u = pyclassinformer.pci_utils.utils()
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        
        vfunc_eas = data[vftable_ea].vfeas
        
        for index, vfea in enumerate(vfunc_eas):
            entry_ea = vftable_ea + (index * u.PTR_SIZE)
            comment = format(index)
            ida_bytes.set_cmt(entry_ea, comment, 0)


def get_base_classes(data):
    paths = {}
    for vftable_ea in data:
        # get COL
        col = data[vftable_ea]
        
        # get relevant BCDs mainly for multiple inheritance
        base_classes = pyclassinformer.pci_utils.utils.get_col_bases(col, data)
        
        # reverse the path because the path is reverse ordered.
        base_classes.reverse()
        paths[vftable_ea] = base_classes
    
    # sort the results by the class name and base class length
    return {x:paths[x] for x in sorted(sorted(paths, key=lambda key: [x.name for x in paths[key]]), key=lambda key: len(paths[key]))}


def method_classifier(data, config=None, icon=-1):
    if config is None:
        config = pyclassinformer.pci_config.pci_confg()
        
    # check config values to execute or not
    if not config.exana and not config.mvvm and not config.mvcd and not config.rnvm and not config.rncd and not config.rnvi:
        return None
    
    # get base classes
    paths = get_base_classes(data)
    
    # rename virtual methods in vftables
    if config.rnvm:
        rename_vfuncs(paths, data)

    # rename functions that refer to vftables because they are constructors or destructors
    if config.rncd:
       rename_vftable_ref_funcs(paths, data)
    
    # add virtual function index comments
    if config.rnvi:
        add_vfunc_index_comments(paths, data)
        
    tree = None
    if tree_categorize:
        # get dirtree and move vfuncs to their class directories
        for dirtype in [ida_dirtree.DIRTREE_FUNCS, ida_dirtree.DIRTREE_NAMES]:
            dirtree = ida_dirtree.get_std_dirtree(dirtype)
            if config.mvvm:
                change_dir_of_vfuncs(paths, data, dirtree)
            if config.mvcd:
                change_dir_of_ctors_dtors(paths, data, dirtree)
        
        # display dir tree
        if config.exana:
            tree = pyclassinformer.mc_tree.show_mc_tree_t(data, paths, icon=icon)
    else:
        print("Warning; Your IDA does not have ida_dirtree or find_entry in dirtree_t. Skip creating dirs for classes and moving functions into them.")
    
    return tree

