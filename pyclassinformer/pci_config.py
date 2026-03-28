try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

class pci_config(object):
    
    alldata = True
    rtti = True
    exana = True
    mvvm = True
    mvcd = True
    rnvm = True
    rncd = True
    rnvi = False
    dirtree = True
    
    def __init__(self, alldata=False, rtti=True, exana=True, mvvm=True, mvcd=True, rnvm=True, rncd=True, rnvi=True):
        self.alldata = alldata
        self.rtti = rtti
        self.exana = exana
        self.mvvm = mvvm
        self.mvcd = mvcd
        self.rnvm = rnvm
        self.rncd = rncd
        self.rnvi = rnvi
        self.check_dirtree()
        
    def check_dirtree(self):
        try:
            import ida_dirtree
            ida_dirtree.dirtree_t.find_entry
        # for IDA 7.x
        except (ModuleNotFoundError, AttributeError) as e:
            self.exana = False
            self.mvvm = False
            self.mvcd = False
            self.dirtree = False
            
