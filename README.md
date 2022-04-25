OOUtils
-------

A Ghidra extension that aims to make reverse engineering of object-oriented langauges easier. Currently in *very* early dev. 

To build, make sure your GHIDRA_HOME environment variable is set to the version of Ghidra you're going to install this in, then just run:

```
gradle buildExtension
```

The installable zip will be in the `dist` folder. Install like any other ghidra plugin. 

Currently, only the SpawnNewClassFromVtable and UpdateVtableFunctionDefinitions scripts should be used. 
* To use the SpawnNewClassFromVtable script, clear all the data occupying a vtable, click on the start of the vtable in the listing view, and then run the script. You'll be asked to provide a name for the class (can include preceding namespaces), and a number of pointers. If everything goes well, the class symbol, the vtable struct, the class struct, etc, will all be created for you in the symbol tree and in the "OOUtils_Managed" folder in the datatype manager. 
* To use the UpdateVtableFunctionDefinitions script, click on the start of a vtable created with OOUtils, then run the script from the script manager or some hotkey. Virtual function definitions that we can safely assume are owned exclusively by the vtable's class will be updated for you!
    - In order to keep things safe, this will only update for functions that are referenced by the vtable and whose namespace is the same as the class namespace. You can add non-automatically-claimed functions to the namespace manually if you want to make that function pointer automatically update.

Next steps as of the last time this readme was updated:
- Adding/subtracting vtable slots
- Automatic constructor location using data references
- Some sort of basic UI

If you have features you want to see added, by all means, please request them! Worst thing I can do is say no. Pull requests are also welcome.

If it feels like this is bad code, it probably is. I've never written a single Java project prior to this other than relatively short single-function ghidra scripts. If you have tips, please submit an issue. 