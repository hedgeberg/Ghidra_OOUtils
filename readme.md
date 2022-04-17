OOUtils
-------

A Ghidra extension that aims to make reverse engineering of object-oriented langauges easier. Currently in *very* early dev. 

Build the same way you build any ghidra extension. If you don't know how, this probably isn't for you just yet.

Currently, the only particularly useful functionality is the SpawnNewClassFromVtable script. To use, clear all the data occupying a vtable, click on the start of the vtable in the listing view, and then run the script. You'll be asked to provide a name for the class (can include preceding namespaces), and a number of pointers. If everything goes well, the class symbol, the vtable struct, the class struct, etc, will all be created for you in the symbol tree and in the "OOUtils_Managed" folder in the datatype manager. 

Next steps as of the last time this readme was updated:
-Automatic virtual member function updating
-Automatic constructor location using data references
-Some sort of basic UI

If it feels like this is bad code, it probably is. I've never written a single Java project prior to this other than relatively short single-function ghidra scripts. If you have tips, please submit an issue. 
