import ida_idaapi
import ida_kernwin


# --------------------------------------------------------------------------
class pci_form_t(ida_kernwin.Form):

    def __init__(self, dirtree=True):
        self.invert = False
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""PyClassInformer Options

{FormChangeCb}

<##Search area##Only .rdata section:{rdata}> <##All data sections:{alldata}>{search_area}>

<##Actions##Display RTTI parsed results on the Output window:{rtti}>
<##Display extra analysis result (IDA 7.7 or later):{exana}>
<##Create folders for classes and move virtual methods to them in Functions and Names subviews (IDA 7.7 or later):{mvvm}>
<##Move functions refer vftables to "possible ctors or dtors" folder under each class folder in Functions and Names subviews (IDA 7.7 or later):{mvcd}>
<##Rename virtual methods:{rnvm}>
<##Append virtual index comment:{rnvi}>
<##Rename possible constructors and destructors:{rncd}>{acts}>
""", {
            'FormChangeCb': F.FormChangeCb(self.OnFormChange),
            'search_area': F.RadGroupControl(("rdata", "alldata")),
            'acts': F.ChkGroupControl(("rtti", "exana", "mvvm", "mvcd", "rnvm", "rnvi", "rncd")),
        })
        
        self.dirtree = dirtree
        self.executed = False
        
        # Compile (in order to populate the controls)
        self.Compile()
        self.set_default_settings()
        
    def OnFormChange(self, fid):
        # set only once when it is called
        if not self.executed:
            self.change_dirtree_settings()
            self.executed = True
        return 1
        
    def change_dirtree_settings(self):
        self.SetControlValue(self.exana, True)
        self.SetControlValue(self.mvvm, True)
        self.SetControlValue(self.mvcd, True)
        if not self.dirtree:
            self.EnableField(self.exana, False)
            self.EnableField(self.mvvm, False)
            self.EnableField(self.mvcd, False)
            self.SetControlValue(self.exana, False)
            self.SetControlValue(self.mvvm, False)
            self.SetControlValue(self.mvcd, False)

    def set_default_settings(self):
        self.rdata.selected = True
        self.rtti.checked = True
        self.exana.checked = True
        self.mvvm.checked = True
        self.mvcd.checked = True
        self.rnvm.checked = True
        self.rnvi.checked = False
        self.rncd.checked = True
        
    @staticmethod
    def show():
        ida_idaapi.require("pyclassinformer")
        ida_idaapi.require("pyclassinformer.pci_config")
        pcic = pyclassinformer.pci_config.pci_config()
        f = pci_form_t(dirtree=pcic.dirtree)

        # Execute the form
        ok = f.Execute()
        if ok == 1:
            pcic = pyclassinformer.pci_config.pci_config(alldata=f.alldata.selected, rtti=f.rtti.checked, exana=f.exana.checked, mvvm=f.mvvm.checked, mvcd=f.mvcd.checked, rnvm=f.rnvm.checked, rnvi=f.rnvi.checked, rncd=f.rncd.checked)
        else:
            return None

        # Dispose the form
        f.Free()
        return pcic

"""
ida_idaapi.require("pci_config")
pcic = pci_form_t.show()
if pcic is not None:
    print(pcic.alldata, pcic.exana, pcic.mvvm, pcic.mvcd, pcic.rnvm, pcic.rncd)
"""
