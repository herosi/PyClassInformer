import ida_kernwin
import ida_funcs
import ida_idaapi

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.qtutils")


def get_chooser_data(chooser="Functions"):
    cri = ida_kernwin.chooser_row_info_vec_t()
    ida_kernwin.get_chooser_rows(cri, "Functions", 0)
    if cri.size() == 0:
        # for IDA 9.3
        # The version might have a bug and it crashes when calling
        # get_chooser_rows with GCRF_ALL
        # To avotid that, return None if the first line returns empty.
        return None
    ida_kernwin.get_chooser_rows(cri, chooser, ida_kernwin.GCRF_ALL)
    return cri

def get_func_color(cri, f):
    if f:
        for r in cri:
            fea = int(r.texts[2],16)
            color = r.attrs.color
            if fea == f.start_ea:
                return color
    return -1

def get_libfunc():
    for n in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(n)
        if f.flags & ida_funcs.FUNC_LIB:
            return f
    return None

def get_genfunc():
    for n in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(n)
        if not f.flags & ida_funcs.FUNC_LIB and not f.flags & ida_funcs.FUNC_LUMINA and not f.flags & ida_funcs.FUNC_THUNK:
            return f
    return None

def get_gen_lib_func_colors():
    try:
        # IDA 8.4 or later only has chooser_row_info_vec_t and get_chooser_rows
        cri = get_chooser_data()
    except AttributeError:
        cri = None
        
    gen_func_color = -1
    lib_func_color = -1
    
    if cri is not None:
        f = get_genfunc()
        gen_func_color = get_func_color(cri, f)

        f = get_libfunc()
        lib_func_color = get_func_color(cri, f)
        
    #print(hex(gen_func_color), hex(lib_func_color))
    
    # if something is wrong, set default colors
    if gen_func_color < 0:
        gen_func_color = 0xffffffff
    if lib_func_color < 0:
        lib_func_color = 0xffffffe9
        dark = False
        # check if dark mode is enabled or not
        try:
            dark = pyclassinformer.qtutils.dark_mode_checker_t.is_dark_mode()
        except:
            pass
        # set the default dark mode color on IDA
        if dark:
            lib_func_color = 0xff685328
    
    return gen_func_color, lib_func_color

#print([hex(x) for x in get_gen_lib_func_colors()])
