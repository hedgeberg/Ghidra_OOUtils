OOUtils
-------

A Ghidra extension that aims to make reverse engineering of object-oriented langauges easier. Currently in unstable alpha.  

To build, make sure your GHIDRA_HOME environment variable is set to the version of Ghidra you're going to install this in, then just run:

```
gradle buildExtension
```

The installable zip will be in the `dist` folder. Install like any other ghidra plugin. 

Current valid scripts are:
 - *InstantSpawnClass.java* (spawns a 1-slot vtable for you, just needs a name)
 - *SpawnNewClassFromVtable.java* (spawns an n-slot vtable for you, given n and a name)
 - *GrowVtableByOne.java* (Does what it says on the tin)
 - *ShrinkVtableByOne.java* (Does what it says on the tin)
 - *RenameOOUtilsClass.java* (Renames the class, class struct datatype, etc)
 - *UpdateVtableFunctionDefintions.java* (Iterates through vfuncs and updates their vtable function pointer type defintions)

To use any of these scripts, click on the start of the vtable and launch the script. It's that easy! Should hold your hand from there, if anything is unclear please submit a bug report! In order to keep things safe, the UpdateVtableFunctionDefinitions script will only update for functions that are referenced by the vtable and whose namespace is the same as the class namespace. You can add non-automatically-claimed functions to the namespace manually if you want to make that function pointer automatically update.

Next steps as of the last time this readme was updated:
- 
- Automatic constructor location using data references
- Some sort of basic UI

If you have features you want to see added, by all means, please request them! Worst thing I can do is say no. Pull requests are also welcome.

If it feels like this is bad code, it probably is. I've never written a single Java project prior to this other than relatively short single-function ghidra scripts. If you have tips, please submit an issue. 