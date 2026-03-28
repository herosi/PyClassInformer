# PyClassInformer
## Yet Another RTTI Parsing IDA plugin
![PyClassInformer Icon](/pyclassinformer/pci_icon.png)

PyClassInformer is an RTTI parser. Although there are several RTTI parsers such as Class Informer and SusanRTTI, and even IDA can also parse RTTI, I created this tool. It is because they cannot be used as libraries for parsing RTTI. IDA cannot easily manage class hierarchies such as checking them as a list and filtering the information, either.

**PyClassInformer can parse RTTI on PE formatted binaries compiled by MSVC++ for x86, x64, ARM and ARM64**. Since it is written in IDAPython, you can run it on IDA for Mac OS and Linux as well as Windows. You can also use results of parsing RTTI in your python code by importing this tool as a library.

## Usage
Launch it by pressing Alt+Shift+L. Or navigate to Edit -> Plugins -> PyClassInformer.  
Then, select the options. In most cases, the default options should remain unchanged.

## Installation
Put "pyclassinformer_plugin.py" and "pyclassinformer" folder including the files under it into the "plugins" folder of IDA's user directory ($IDAUSR).  
If you use IDA 8.5 or later and want to manage this plugin with a directory, make a directory like "pci_plugin" in "plugins", copy "ida-plugin.json" into it as well as the files and the folders above.

See the URL if you don't know about "$IDAUSR".  
[https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/)  
[https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml](https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml)

## Requirements
- IDA Pro 7.4 or later (I tested on 7.4 SP1 to 9.3)
- Python 3.x (I tested on Python 3.8, 3.10 and 3.12)

You will need at least IDA Pro 7.4 or later because of the APIs that I use. If you want to use full features, use IDA 8.3 or later. Otherwise, some features will be limited to use or skipped.

## Features (short)
- Display class names, vftables and class hierarchies as a list
- Display RTTI parsed results on the Output window
- Display vftables, class names, virtual methods, possible constructors and destructors, and class hierarchies as a dir tree (IDA 7.7 or later)
- Create directories for classes and move virtual methods to them in Functions and Names subviews (IDA 7.7 or later)
- Move functions refer vftables to "possible ctors or dtors" folder under each class directory in Functions and Names subviews (IDA 7.7 or later)
- Rename virtual methods by appending class names to them
- Add the FUNC_LIB flag to methods that known classes own
- Rename possible constructors and destructors
- Coloring known class names and their methods on the list and the tree widgets (IDA 8.3 or later)

## Features in detail
### Default output
![PyClassInformer Result](/images/result.png)
The image above is an example of PyClassInformer result. And the image below is an example of the original Class Informer result.  
  
![Original ClassInformer Result](/images/orig_class_informer.png)  
  
As you see, almost all columns match the original ones.   
  
In addition, PyClassInformer has two more columns. One is "offset", which shows the offset of a vftable in a class layout.  
  
Another one named "Hierarchy Order" shows class hierarchy information related to a vftable of a line. The column shows the order of inheritance from the class to the top-most super class.  
  
These are useful for grasping class layouts and class hierarchies. Double-clicking a line navigates to its vftable address as well.

### RTTI parsed results
If you check the Output window, you will also see parsed RTTI information such as Complete Object Locator as COL, Class Hierarchy Descriptor as CHD and Base Class Descriptor as BCD with their addresses. They are useful for checking more details and debugging.  
  
![Class Hierarchy](/images/class_hierarchy.png)  

You will also see class hierarchies by checking indents of BCDs. For example, CMFCComObject, which is the class for the vftable at 0x530fcc, inherits ATL::CAccessibleProxy. And ATL::CAccessibleProxy inherits three super classes, ATL::CComObjectRootEx, ATL::IAccessibleProxyImpl and IOleWindow. Like this, you can get class hierarchy information as a form of a tree.

### Automatic renaming
PyClassInformer can automatically append class names to their virtual method names. Therefore, you can easily find them by filtering the class name. The image below is a result appending a class name "CDC" to its methods.  

![automatically renaming virtual methods](/images/auto_renmaing.png)  
  
PyClassInformer can also rename functions that refer to vftables to "class name" + "_possible_ctor_or_dtor". The image below is a result. Although some false positives will occur due to inlined ctors and dtors, and dynamic initializers, this feature is still useful to find them.  
  
![automatically renaming possible ctors and dtors](/images/auto_renmaing2.png)  

### Virtual method classification (<= IDA 7.7)
The detected methods are moved to each class folder in Functions and Names subviews.  
> [!NOTE]
> This is only available IDA 7.7 or later. 
  
![method classifications](/images/classification.png)  
  
PyClassInformer also displays a new widget named "Method Classifier". It lists all detected classes, vftables, virtual methods and possible constructors and destructors, and class hierarchies at once as a form of a tree.  

![method classifier](/images/method_classifier.png)  

> [!TIP]
> Class hierarchies are represented as directories in Method Classifier.
> Unfortunately, IDA's quick filter feature cannot filter directory contents.
> To search them, use text search feature (Ctrl+T (find first text) and Alt+T (Find next text)).
> For example, input a class name, a single space, and a parenthesis like "CWinApp (".

> [!NOTE]
> This is only available IDA 7.7 or later. 

### Known classes detection (<= IDA 8.3)
PyClassInformer can color known class names for easily finding user-defined classes.
The image below is an example of a coloring result.  
You can easily find CSimpleTestApp, CSimpleTestDoc, CSimpleTestView and CSimpleTestCtrlItem are user-defined classes. So you can focus on checking them.  
  
![Class coloring](/images/coloring.png)  

The coloring is also applied to Method Classifier widget. Therefore, you can easily find overridden virtual methods like the image below.  

![Methods coloring](/images/overridden_methods.png)  
  
> [!NOTE]
> The coloring feature is only available IDA 8.3 or later. 
  
Known class names are defined in "lib_classes.json". I added many patterns related to STL, which starts with "std::", and several versions of MFC Application with MFC Application Wizard.  
If you find some additional legitimate classes, you can add them to it.  

PyClassInformer also adds the FUNC_LIB flag to the methods that match the list. Therefore, you can recognize they are a part of static linked libraries.  
The following images are before and after PyClassInformer execution. Many known class methods are found and IDA can recognize them as a part of static linked libraries.  
  
![Methods coloring](/images/before_libflag_applied.png)  
![Methods coloring](/images/after_libflag_applied.png)  

## Note
- I **WILL NOT** support parsing GCC's RTTI. **DO NOT** open an issue about it.
- I **WILL NOT** support beta versions of IDA. **DO NOT** open an issue about it.
- I **WILL NOT** support IDA free and IDA demo except for IDA Classroom Free because they do not have IDAPython.
- Some code is from SusanRTTI and the output table is similar to Class Informer.  
[https://github.com/nccgroup/SusanRTTI](https://github.com/nccgroup/SusanRTTI)  
[https://sourceforge.net/projects/classinformer/](https://sourceforge.net/projects/classinformer/)
