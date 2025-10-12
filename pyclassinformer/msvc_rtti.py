import idc
import ida_idaapi
import ida_typeinf
import ida_offset
import ida_bytes
import ida_nalt
import ida_xref
import ida_kernwin
import ida_auto
import ida_name
import ida_ida
import ida_idp

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

ida_9_or_later = False
try:
    from ida_struct import get_struc
except ModuleNotFoundError:
    ida_9_or_later = True
    # for IDA 9.0
    def get_struc(struct_tid):
        tif = ida_typeinf.tinfo_t()
        if tif.get_type_by_tid(struct_tid):
            if tif.is_struct():
                return tif
        return None

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
u = pyclassinformer.pci_utils.utils()


class RTTIStruc(object):
    tid = 0
    struc = 0
    size = 0
    

def strip(name):
    if name.startswith("class ") and name.endswith("`RTTI Type Descriptor'"):
        return name[6:-23]
    elif name.startswith("struct ") and name.endswith("`RTTI Type Descriptor'"):
        return name[7:-23]
    else:
        return name


class RTTITypeDescriptor(RTTIStruc):
    
    # create structure
    msid = idc.get_struc_id("RTTITypeDescriptor")
    if msid != ida_idaapi.BADADDR:
        idc.del_struc(msid)
    msid = idc.add_struc(0xFFFFFFFF, "RTTITypeDescriptor", False)
    
    # add members
    if u.x64:
        idc.add_struc_member(msid, "pVFTable", ida_idaapi.BADADDR, ida_bytes.FF_DATA|u.PTR_TYPE|ida_bytes.FF_0OFF, -1, u.PTR_SIZE, reftype=u.REF_OFF)
    else:
        idc.add_struc_member(msid, "pVFTable", ida_idaapi.BADADDR, ida_bytes.FF_DATA|u.PTR_TYPE|ida_bytes.FF_0OFF, -1, u.PTR_SIZE)
    idc.add_struc_member(msid, "spare", ida_idaapi.BADADDR, ida_bytes.FF_DATA|u.PTR_TYPE, -1, u.PTR_SIZE)
    idc.add_struc_member(msid, "name", ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_STRLIT, ida_nalt.STRTYPE_C, 0)
    
    # get structure related info
    tid = msid
    struc = get_struc(tid)
    size = idc.get_struc_size(tid)
    print("Completed Registering RTTITypeDescriptor")

    def __init__(self, ea):
        self.class_name = None
        self.ea = ea
        
        # get name and len
        name = ea + u.get_moff_by_name(self.struc, "name")
        strlen = u.get_strlen(name)
        if strlen is None:
            # not a real vtable
            return
        self.size = self.size + strlen + 1 # for NULL byte
        
        # get mangled name
        bmangled = ida_bytes.get_strlit_contents(name, strlen, 0)
        if bmangled is None:
            # not a real function name
            return
        mangled = bmangled.decode('UTF-8')
        
        # get demangled name
        #print("Mangled: " + mangled)
        demangled = ida_name.demangle_name('??_R0' + mangled[1:] , 0)
        if demangled:
            # apply structure type to bytes
            #print("Demangled: " + demangled)
            ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, self.size)
            if ida_bytes.create_struct(ea, self.size, self.tid):
                #print("  Made td at 0x%x: %s" % (ea, demangled))
                self.class_name = demangled
                return
        print("  FAIL :(")
        return


class RTTIClassHierarchyDescriptor(RTTIStruc):
    
    CHD_MULTINH   = 0x01 # Multiple inheritance
    CHD_VIRTINH   = 0x02 # Virtual inheritance
    CHD_AMBIGUOUS = 0x04 # Ambiguous inheritance
    
    # create structure
    msid = idc.get_struc_id("RTTIClassHierarchyDescriptor")
    if msid != ida_idaapi.BADADDR:
        idc.del_struc(msid)
    msid = idc.add_struc(0xFFFFFFFF, "RTTIClassHierarchyDescriptor", False)

    # add members
    idc.add_struc_member(msid, "signature", ida_idaapi.BADADDR, ida_bytes.FF_DWORD|ida_bytes.FF_DATA, -1, 4)
    idc.add_struc_member(msid, "attribute", ida_idaapi.BADADDR, ida_bytes.FF_DWORD|ida_bytes.FF_DATA, -1, 4)
    idc.add_struc_member(msid, "numBaseClasses", ida_idaapi.BADADDR, ida_bytes.FF_DWORD|ida_bytes.FF_DATA, -1, 4)
    idc.add_struc_member(msid, "pBaseClassArray", ida_idaapi.BADADDR, ida_bytes.FF_DWORD|ida_bytes.FF_DATA, -1, 4) # for dummy. the correct type will be applied when the BCA class is created.
    
    # get structure related info
    tid = msid
    struc = get_struc(tid)
    size = idc.get_struc_size(tid)
    print("Completed Registering RTTIClassHierarchyDescriptor")

    def __init__(self, ea):
        self.ea = ea
        self.sig = 0
        self.bcaea = ida_idaapi.BADADDR
        self.nb_classes = 0
        self.flags = ""
        self.bca = None
        
        # apply structure type to bytes
        ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, self.size)
        if ida_bytes.create_struct(ea, self.size, self.tid):
            # Get members of CHD
            self.sig = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "signature"))
            self.attribute = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "attribute"))
            self.nb_classes = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "numBaseClasses"))
            self.bcaea = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "pBaseClassArray")) + u.x64_imagebase()
            
            self.bca = RTTIBaseClassArray(self.bcaea, self.nb_classes)
            
            # parse flags
            if self.attribute & self.CHD_MULTINH:
                self.flags += "M"
            if self.attribute & self.CHD_VIRTINH:
                self.flags += "V"
            if self.attribute & self.CHD_AMBIGUOUS:
                self.flags += "A"
            #self.flags += " {:#x}".format(self.attribute)
        

class RTTIBaseClassDescriptor(RTTIStruc):
    
    BCD_NOTVISIBLE = 0x00000001
    BCD_AMBIGUOUS = 0x00000002
    BCD_PRIVORPROTBASE = 0x00000004
    BCD_PRIVORPROTINCOMPOBJ = 0x00000008
    BCD_VBOFCONTOBJ = 0x00000010
    BCD_NONPOLYMORPHIC = 0x00000020
    BCD_HASPCHD = 0x00000040 # pClassDescriptor field is present
    
    # create structure
    msid = idc.get_struc_id("RTTIBaseClassDescriptor")
    if msid != ida_idaapi.BADADDR:
        idc.del_struc(msid)
    msid = idc.add_struc(0xFFFFFFFF, "RTTIBaseClassDescriptor", False)
    
    # add members
    u.add_ptr_or_rva_member(msid, "pTypeDescriptor", "RTTITypeDescriptor")
    idc.add_struc_member(msid, "numContainerBases", ida_idaapi.BADADDR, ida_bytes.FF_DWORD|ida_bytes.FF_DATA, -1, 4)
    idc.add_struc_member(msid, "mdisp", ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD, -1, 4) # 00 PMD Vftable displacement inside class layout
    idc.add_struc_member(msid, "pdisp", ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD, -1, 4) # 04 PMD Vbtable displacement
    idc.add_struc_member(msid, "vdisp", ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD, -1, 4) # 08 PMD Vftable displacement inside vbtable
    idc.add_struc_member(msid, "attributes", ida_idaapi.BADADDR, ida_bytes.FF_DWORD|ida_bytes.FF_DATA, -1, 4)
    u.add_ptr_or_rva_member(msid, "pClassDescriptor", "RTTIClassHierarchyDescriptor")
    
    # get structure related info
    tid = msid
    struc = get_struc(tid)
    size = idc.get_struc_size(tid)
    print("Completed Registering RTTIBaseClassDescriptor")
    
    def __init__(self, ea):
        self.ea = ea
        # apply structure type to bytes
        ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, self.size)
        if ida_bytes.create_struct(ea, self.size, self.tid):
            # Get members of BCD
            self.tdea = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "pTypeDescriptor")) + u.x64_imagebase()
            self.nb_cbs = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "numContainerBases"))
            self.mdisp = u.to_signed32(ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "mdisp")))
            self.pdisp = u.to_signed32(ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "pdisp")))
            self.vdisp = u.to_signed32(ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "vdisp")))
            self.attributes = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "attributes"))
            self.chdea = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "pClassDescriptor")) + u.x64_imagebase()
                

class RTTIBaseClassArray(RTTIStruc):
    
    # create structure
    msid = idc.get_struc_id("RTTIBaseClassArray")
    if msid != ida_idaapi.BADADDR:
        idc.del_struc(msid)
    msid = idc.add_struc(0xFFFFFFFF, "RTTIBaseClassArray", False)

    # add members
    u.add_ptr_or_rva_member(msid, "arrayOfBaseClassDescriptors", "RTTIBaseClassDescriptor", array=True)
    
    # get structure related info
    tid = msid
    struc = get_struc(tid)
    size = idc.get_struc_size(tid)
    
    # correct BCA's pBaseClassArray member type here.
    u.set_ptr_or_rva_member(RTTIClassHierarchyDescriptor.tid, "pBaseClassArray", "RTTIBaseClassArray")
    
    print("Completed Registering RTTIBaseClassArray")

    def __init__(self, ea, nb_classes):
        self.ea = ea
        # fix the size with the actual size by using nb_classes from CHD since the size depends on each BCA
        self.size = 4 * nb_classes

        self.bases = []
        self.paths = {}
        self.depth = 0
        
        # apply structure type to bytes
        ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, self.size)
        if ida_bytes.create_struct(ea, self.size, self.tid):
            pass
        
    # Sometimes, mdisp value is not included in COLs' offsets.
    # In that case, use either one of the following:
    #   - in the middle of the BCD's mdisp of a path (for MI with multiple vftables)
    #   - least COL's offset (for other cases such as SI and MI with a single vftable)
    def fix_offset(self, col_offs, curr_path, curr_off):
        # for MI with multiple vftables
        if len(col_offs) > 1:
            #print([(bcd.name, hex(bcd.mdisp)) for bcd in curr_path], [hex(x) for x in col_offs], curr_off)
            if curr_path and curr_path[-1].mdisp in col_offs:
                return curr_path[-1].mdisp
            return curr_off
        # for other cases such as SI and MI with a single vftable
        return sorted(col_offs)[0]
    
    def is_path_added(self, curr_path, offset, vi_offs, col):
        # if the offset has negative value, the path will not be added
        if offset < 0:
            return False
        
        # if the path does not have any VI classes, it will be added.
        if len(vi_offs) == 0:
            return True
        
        # if the path has a VI class and the path is for the current COL, the path will be added.
        if col.offset in vi_offs:
            #print("before comparing paths: current offset {}, col offset {}, vi_offs table {}, curr_path {}, vi_off == curr_path {}, name of vi_off == curr_path {}.".format(offset, col.offset, {x: [y.name for y in vi_offs[x]] for x in vi_offs}, [x.name for x in curr_path], curr_path == vi_offs[col.offset], [x.name for x in vi_offs[col.offset]] == [x.name for x in curr_path]))
            # here, it needs to compare the names instead of instances
            # because they are different on each vftable
            if [x.name for x in vi_offs[col.offset]] == [x.name for x in curr_path]:
                #print("this will be added: current offset {}, col offset {}, vi_offs table {}, curr_path {}.".format(offset, col.offset, {x: [y.name for y in vi_offs[x]] for x in vi_offs}, [x.name for x in curr_path]))
                return True
        return False
    
    # calc final offset mainly for VI
    def fix_offset_final(self, col_offs, curr_path, curr_off, vi_offs, col):
        # get first VI class
        found = False
        bcd = None
        for bcd in curr_path:
            if bcd.pdisp >= 0:
                found = True
                break
            
        # for SI and MI
        if len(col_offs) <= 1 or not found:
            return curr_off
        
        # for VI
        if found:
            found_col = False
            #print("vi_offs:", {x: [y.name for y in vi_offs[x]] for x in vi_offs})
            # get current offset if the current col is already in vi_offs.
            if col.offset in vi_offs:
                curr_off = col.offset
            # if the current col offset is not in vi_offs, the path is not processed yet.
            else:
                for p in vi_offs:
                    # check vi_offs table to get the correct offset by comparing the current
                    # path and paths in the vi_offs.
                    # here, it needs to compare the names instead of instances because they
                    # are different on each vftable
                    if [x.name for x in vi_offs[p]] == [x.name for x in curr_path]:
                        # sometimes, a class has two or more vftables, and a vfptr is at
                        # its COL's offset but anther is not at COL's offsets because of VI.
                        # E.g.
                        # XXXXX::xxx (0,-1,0) -> XXXXX::yyy (0,4,4)
                        # in this case, the current path is necessary on both vftables.
                        # here, a path that is already added in the past will also be added
                        # to another vftable that is not stored in vi_offs yet.
                        if curr_off in col_offs and col.offset != curr_off:
                            pass
                        # otherwise, this path will be skipped adding the current vftable
                        # because it is already processed.
                        else:
                            return -1
                    else:
                        # processing the path is the first time.
                        # this path will be added on the current vftable.
                        pass
                
                # update vi_offs if the offset is empty, processing the path is the first 
                # time, or a special case (see above)
                curr_off = col.offset
                vi_offs[col.offset] = curr_path
                found_col = True

            if not found_col:
                if curr_off not in vi_offs:
                    print("Warning: current offset {} was not found in vi_offs table {}. This should be a virtual inheritance {}.".format(curr_off, {x: [y.name for y in vi_offs[x]] for x in vi_offs}, [x.name for x in curr_path]))
        else:
            print("Warning: current offset {} is not in COL's offset {}. This should be a virtual inheritance. But all pdisp values in the path has negative values. {} {}".format(curr_off, col_offs, [x.pdisp for x in curr_path], [x.name for x in curr_path]))
        return curr_off
    
    def parse_bca(self, col, col_offs, vi_offs):
        ea = col.chd.bca.ea
        nb_classes = col.chd.nb_classes
        
        # parse bca
        for i in range(0, nb_classes):
            bcdoff = ea+i*4
            
            # get relevant structures
            bcdea = ida_bytes.get_32bit(bcdoff) + u.x64_imagebase()
            bcd = RTTIBaseClassDescriptor(bcdea)
            tdea = ida_bytes.get_32bit(bcdea) + u.x64_imagebase()
            td = RTTITypeDescriptor(tdea)
            
            ida_bytes.create_struct(bcd.chdea, RTTIClassHierarchyDescriptor.size, RTTIClassHierarchyDescriptor.tid, True)
            
            # add to result and filter out None entries
            if td.class_name:
                bcd.name = strip(td.class_name)
                self.bases.append(bcd)
                
        # parse hierarchy
        result_paths = {}
        curr_path = []
        n_processed = {}
        curr_off = 0
        for i, bcd in enumerate(self.bases):
            n_processed[bcd.nb_cbs] = 0
            
            # add BCD to the current path
            curr_path.append(bcd)
            curr_depth = len(curr_path) - 1
            
            # update the offset for paths of base classes
            curr_off = self.fix_offset(col_offs, curr_path, curr_off)
        
            # find a path to an offset for multiple inheritance
            if bcd.nb_cbs == 0:
                path = curr_path.copy()
                
                # get the final offset mainluy for VI
                offset = self.fix_offset_final(col_offs, path, curr_off, vi_offs, col)
                
                # append result according to the obtained offset
                if self.is_path_added(path, offset, vi_offs, col):
                    if offset in result_paths:
                        result_paths[offset].append(path)
                    else:
                        result_paths[offset] = [path]
                    
                # rewind current result for next inheritance
                while True:
                    # compare the number of bases to be processed in the current path with the number processed so far.
                    # if they are maatched, the base class must have been processed. So remove it.
                    if n_processed[curr_path[-1].nb_cbs] == curr_path[-1].nb_cbs:
                        # pop the record of the last bcd from the n_processed. and pop the last bcd itself from the current path.
                        #print("before:", [x.name for x in curr_path], n_processed[curr_path[-1].nb_cbs], n_processed)
                        del n_processed[curr_path[-1].nb_cbs]
                        prev_bcd = curr_path.pop()
                        
                        # set the number processed so far to the new tail.
                        if len(curr_path) > 0:
                            n_processed[curr_path[-1].nb_cbs] += prev_bcd.nb_cbs + 1
                        #print("after: ", [x.name for x in curr_path], n_processed[curr_path[-1].nb_cbs] if len(curr_path) > 0 else -1, n_processed)
                            
                    # quit the loop if finished, or no need to unwind for next bcd.
                    if len(curr_path) == 0 or (len(curr_path) > 0 and n_processed[curr_path[-1].nb_cbs] != curr_path[-1].nb_cbs):
                        break
                #print("out of loop:", [x.name for x in curr_path], n_processed[curr_path[-1].nb_cbs] if len(curr_path) > 0 else -1, n_processed)
            
            yield bcd, curr_depth
            
            # update the base class depth
            self.bases[i].depth = curr_depth
                        
        #print({x:[[z.name for z in y] for y in result_paths[x]] for x in result_paths}, col_offs)
        self.paths = result_paths

        if col.offset not in self.paths or not self.paths[col.offset]:
            print("Warning: Dispatching class hierarchy paths of the BCA at {:#x} for {} may be wrong because the paths list for the offset {} is empty. The paths will be misclassified as the wrong offset.".format(ea, self.bases[0].name, col.offset))


class RTTICompleteObjectLocator(RTTIStruc):

    # create structure
    msid = idc.get_struc_id("RTTICompleteObjectLocator")
    if msid != ida_idaapi.BADADDR:
        idc.del_struc(msid)
    msid = idc.add_struc(0xFFFFFFFF, "RTTICompleteObjectLocator", False)
    
    # add members
    idc.add_struc_member(msid, "signature", ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD, -1, 4)
    idc.add_struc_member(msid, "offset", ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD, -1, 4)
    idc.add_struc_member(msid, "cdOffset", ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD, -1, 4)
    u.add_ptr_or_rva_member(msid, "pTypeDescriptor", "RTTITypeDescriptor")
    u.add_ptr_or_rva_member(msid, "pClassDescriptor", "RTTIClassHierarchyDescriptor")
    if u.x64:
        u.add_ptr_or_rva_member(msid, "pSelf", "RTTICompleteObjectLocator")
        
    # get structure related info
    tid = msid
    struc = get_struc(tid)
    size = idc.get_struc_size(tid)
    print("Completed Registering RTTICompleteObjectLocator")

    LIBUNK = 0
    LIBLIB = 1
    LIBNOTLIB = 2
    
    def __init__(self, ea, vtable):
        self.ea = ea
        self.name = None
        self.chd = None
        self.td = None
        self.offset = 0
        self.cdOffset = 0
        self.vfeas = []
        self.libflag = self.LIBUNK
        
        # apply structure type to bytes at ea
        ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, self.size)
        if ida_bytes.create_struct(ea, self.size, self.tid):
            # Get members of COL
            self.sig = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "signature"))
            self.offset = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "offset"))
            self.cdOffset = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "cdOffset"))
            self.tdea = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "pTypeDescriptor")) + u.x64_imagebase()
            self.chdea = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "pClassDescriptor")) + u.x64_imagebase()
            self.selfea = ida_idaapi.BADADDR
            if u.x64:
                self.selfea = ida_bytes.get_32bit(ea+u.get_moff_by_name(self.struc, "pSelf")) + u.x64_imagebase()
                
            # get TD to get the class name
            td = RTTITypeDescriptor(self.tdea)
            # validate the COL if the TD has a valid class name or not
            if td.class_name:
                # parse relevant structures
                self.td = td
                self.chd = RTTIClassHierarchyDescriptor(self.chdea)
                self.vfeas = [x for x in pyclassinformer.pci_utils.get_vtbl_methods(vtable)]
                
                # set class name
                self.name = strip(self.td.class_name)
                
                # set vftable name
                if ida_name.get_name(vtable).startswith("off_"):
                    ida_name.set_name(vtable, "vtable__" + self.name, ida_name.SN_NOWARN)
            else:
                # if the RTTITypeDescriptor doesn't have a valid name for us to
                # read, then this wasn't a valid RTTICompleteObjectLocator
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, self.size)


class rtti_parser(object):
    
    platforms = [ida_idp.PLFM_386, ida_idp.PLFM_ARM]
    formats = [ida_ida.f_PE]
    
    @staticmethod
    def parse(start, end):
        data_size = end-start
       
        # for RTTI relevant structures creation
        ida_auto.auto_wait()
    
        # get COLs with CHDs and TDs
        result = {}
        for offset in range(0, data_size-u.PTR_SIZE, u.PTR_SIZE):
            vtable = start+offset
            if u.is_vtable(vtable):
                colea = u.get_ptr(vtable-u.PTR_SIZE)
                if u.within(colea, u.valid_ranges):
                    col = RTTICompleteObjectLocator(colea, vtable)
                    # add rcol to the results
                    if col.name is not None:
                        result[vtable] = col
                        
        # may be this is a bug on IDA.
        # ida fails to apply a structure type to bytes under some conditions, although create_struct returns True.
        # to avoid that, apply them again. Cache xref targets per tid to avoid repeated calls.
        ida_auto.auto_wait()

        # helper: get xref set for a tid (cache)
        def get_xref_set(tid):
            return set(u.get_refs_to(tid))

        # build caches of expected addresses
        found_col_eas = [result[x].ea for x in result]
        found_chd_eas = set([result[x].chd.ea for x in result])
        found_td_eas = set([result[x].td.ea for x in result])

        # apply structs only to addresses missing from IDA's xref results
        col_xrefs = get_xref_set(RTTICompleteObjectLocator.tid)
        if len(col_xrefs) != len(found_col_eas):
            for ea in found_col_eas:
                if ea not in col_xrefs:
                    ida_bytes.create_struct(ea, RTTICompleteObjectLocator.size, RTTICompleteObjectLocator.tid, True)

        chd_xrefs = get_xref_set(RTTIClassHierarchyDescriptor.tid)
        if len(chd_xrefs) != len(found_chd_eas):
            for ea in found_chd_eas:
                if ea not in chd_xrefs:
                    ida_bytes.create_struct(ea, RTTIClassHierarchyDescriptor.size, RTTIClassHierarchyDescriptor.tid, True)

        td_xrefs = get_xref_set(RTTITypeDescriptor.tid)
        if len(td_xrefs) != len(found_td_eas):
            for ea in found_td_eas:
                if ea not in td_xrefs:
                    # find corresponding td size from result mapping
                    # result[x].td.size may be different; safe fallback to RTTITypeDescriptor.size
                    td_size = next((result[x].td.size for x in result if result[x].td.ea == ea), RTTITypeDescriptor.size)
                    ida_bytes.create_struct(ea, td_size, RTTITypeDescriptor.tid, True)

        # for refreshing xrefs to get xrefs from COLs to TDs
        ida_auto.auto_wait()
        
        # parse BCA
        prev_col = None
        vi_offs = {}
        for vtable in result:
            col = result[vtable]
            col_offs = u.get_col_offs(col, result)
            if prev_col and prev_col.name != col.name:
                vi_offs = {}
            
            # get BCDs
            for bcd, depth in col.chd.bca.parse_bca(col, col_offs, vi_offs):
                pass
            prev_col = col
        
        # may be this is a bug on IDA.
        # ida fails to apply a structure type to bytes under some conditions, although create_struct returns True.
        # to avoid that, apply them again.
        ida_auto.auto_wait()
        #print(len([xrea for xrea in u.get_refs_to(RTTIBaseClassArray.tid)]), len(set([result[x].chd.bca.ea for x in result])))
        if len([xrea for xrea in u.get_refs_to(RTTIBaseClassArray.tid)]) != len(set([result[x].chd.bca.ea for x in result])):
            [ida_bytes.create_struct(result[x].chd.bca.ea, result[x].chd.bca.size, RTTIBaseClassArray.tid, True) for x in result]
        #print(len([xrea for xrea in u.get_refs_to(RTTIClassHierarchyDescriptor.tid)]), len(set([result[x].chd.ea for x in result])))
        if len([xrea for xrea in u.get_refs_to(RTTIClassHierarchyDescriptor.tid)]) != len(set([result[x].chd.ea for x in result])):
            [ida_bytes.create_struct(result[x].chd.ea, RTTIClassHierarchyDescriptor.size, RTTIClassHierarchyDescriptor.tid, True) for x in result]
        #print(len([xrea for xrea in u.get_refs_to(RTTIBaseClassDescriptor.tid)]), len(set([y.ea for x in result for y in result[x].chd.bca.bases])))
        if len([xrea for xrea in u.get_refs_to(RTTIBaseClassDescriptor.tid)]) != len(set([y.ea for x in result for y in result[x].chd.bca.bases])):
            [[ida_bytes.create_struct(y.ea, RTTIBaseClassDescriptor.size, RTTIBaseClassDescriptor.tid, True) for y in result[x].chd.bca.bases] for x in result]
        #print(len([xrea for xrea in u.get_refs_to(RTTITypeDescriptor.tid)]), len(set([y.tdea for x in result for y in result[x].chd.bca.bases])))
        if len([xrea for xrea in u.get_refs_to(RTTITypeDescriptor.tid)]) != len(set([y.tdea for x in result for y in result[x].chd.bca.bases])):
            [[ida_bytes.create_struct(y.tdea, RTTITypeDescriptor.size, RTTITypeDescriptor.tid, True) for y in result[x].chd.bca.bases] for x in result]
        if len([xrea for xrea in u.get_refs_to(RTTIClassHierarchyDescriptor.tid)]) != len(set([result[x].chd.ea for x in result] + [y.chdea for x in result for y in result[x].chd.bca.bases])):
            [[ida_bytes.create_struct(y.chdea, RTTIClassHierarchyDescriptor.size, RTTIClassHierarchyDescriptor.tid, True) for y in result[x].chd.bca.bases] for x in result]
        ida_auto.auto_wait()
    
        # for debugging
        if len([xrea for xrea in u.get_refs_to(RTTICompleteObjectLocator.tid)]) != len([result[x].ea for x in result]):
            print("Warning: RTTICompleteObjectLocator found and its xrefs are not matched (xrefs:{}, found: {})".format(len([xrea for xrea in u.get_refs_to(RTTICompleteObjectLocator.tid)]), len([result[x].ea for x in result])))
        if len([xrea for xrea in u.get_refs_to(RTTIClassHierarchyDescriptor.tid)]) != len(set([result[x].chd.ea for x in result] + [y.chdea for x in result for y in result[x].chd.bca.bases])):
            print("Warning: RTTIClassHierarchyDescriptor found and its xrefs are not matched (xrefs:{}, found: {})".format(len([xrea for xrea in u.get_refs_to(RTTIClassHierarchyDescriptor.tid)]), len(set([result[x].chd.ea for x in result] + [y.chdea for x in result for y in result[x].chd.bca.bases]))))
        if len([xrea for xrea in u.get_refs_to(RTTITypeDescriptor.tid)]) != len(set([y.tdea for x in result for y in result[x].chd.bca.bases])):
            print("Warning: RTTITypeDescriptor found and its xrefs are not matched (xrefs:{}, found: {})".format(len([xrea for xrea in u.get_refs_to(RTTITypeDescriptor.tid)]), len(set([y.tdea for x in result for y in result[x].chd.bca.bases]))))
        if len([xrea for xrea in u.get_refs_to(RTTIBaseClassArray.tid)]) != len(set([result[x].chd.bca.ea for x in result])):
            print("Warning: RTTIBaseClassArray found and its xrefs are not matched (xrefs:{}, found: {})".format(len([xrea for xrea in u.get_refs_to(RTTIBaseClassArray.tid)]), len(set([result[x].chd.bca.ea for x in result]))))
        if len([xrea for xrea in u.get_refs_to(RTTIBaseClassDescriptor.tid)]) != len(set([y.ea for x in result for y in result[x].chd.bca.bases])):
            print("Warning: RTTIBaseClassDescriptor found and its xrefs are not matched (xrefs:{}, found: {})".format(len([xrea for xrea in u.get_refs_to(RTTIBaseClassDescriptor.tid)]), len(set([y.ea for x in result for y in result[x].chd.bca.bases]))))
        return result

    @staticmethod
    def is_binary_allowed():
        if ida_idp.ph.id not in rtti_parser.platforms:
            print("[PyClassInformer] Warning: The platform is not supported ({:#x}). This only supports x86, x64, ARM and ARM64.".format(ida_idp.ph.id))
            return False
        if ida_ida.inf_get_filetype() not in rtti_parser.formats:
            import ida_loader
            print("[PyClassInformer] Warning: The binary format is not supported ({}). This only supports PE.".format(ida_loader.get_file_type_name()))
            return False
        return True
        
    @staticmethod
    def show(result):
        for vtable in result:
            col = result[vtable]
            print("vtable at : " + hex(vtable))
            print("  COL at {:#x}:".format(col.ea), col.name, col.sig, col.offset, col.cdOffset, hex(col.tdea), hex(col.chdea), hex(col.selfea) if col.selfea != ida_idaapi.BADADDR else "")
            print("  CHD at {:#x}:".format(col.chd.ea), hex(col.chd.sig), col.chd.flags, col.chd.nb_classes, hex(col.chd.bcaea))
            
            # get BCDs
            for bcd in col.chd.bca.bases:
                print("    {}BCD at {:#x}:".format(" " *bcd.depth*2, bcd.ea), bcd.name, hex(bcd.tdea), bcd.nb_cbs, bcd.mdisp, bcd.pdisp, bcd.vdisp, bcd.attributes, hex(bcd.chdea))

    @staticmethod
    def run(alldata=False, icon=-1):
        result = {}
        
        # check if the binary you loaded is valid or not.
        if not rtti_parser.is_binary_allowed():
            return result
        
        # find vftables with relevant structures
        if u.rdata and not alldata:
            result = rtti_parser.parse(u.rdata.start_ea, u.rdata.end_ea)
        # if .rdata was not found, try multiple data segments
        else:
            # expand ranges to check to all data
            u.update_valid_ranges()
            
            # get all data segments' results
            for seg in u.get_data_segments():
                result.update(rtti_parser.parse(seg.start_ea, seg.end_ea))
        return result
    
