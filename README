afl crash analyzer: Another crash analysis and triage tool for American Fuzzy Lop (AFL) results.

Goals of this project:
- Simple, flexible python scripts for crash analysis, if dependencies allow it the scripts are standalone tools as well (see FileDuplicateFinder.py)
- Everything file based (no database)
- There is no command line argument parsing planned (except for the standalone tools), but you have to modify the main python script to your preferences

Features:
1. Crash input file deduplication (on filesize + md5), renaming of duplicate names (or all files), removing README.txt files. This part is now additionally a standalone command line tool (FileDuplicateFinder.py) that can be used independently from the project
2. Running binary with each crash input file and divide the input file into folders for each signal
3. For crash input files that create signals you are interested in you can:
  4. Run the binary and put stdout/stderr into a .txt file next to the crash input file
    5. The same for ASAN enabled binaries to get ASAN output
    6. Run the binary with gdb in batch mode and a configurable gdb script (for example including the "exploitable" gdb script). Remember: the exploitable gdb plugin lies *a lot*.
     7. If you run the exploitable gdb plugin you can divide into subfolders again (EXPLOITABLE, PROBABLY_EXPLOITABLE, etc.)
8. Minimize input crashes with afl-tmin, deduplication on the results and the same procedure again as described in 4.-7.

Installation:
0. Install AFL
1. Prepare your linux box, do whatever makes sense for a fuzzing machine, for example:
 a) sudo apt-get remove whoopsie
2. Install exploitable gdb script if you want to use it
3. Compile binaries (one plain, one ASAN, one instrumented is recommended) if you haven't already (see install.sh files in testcases folder for examples)
4. Start with reading AflCrashAnalyzer.py and configure the CrashAnalysisConfig object in there (examples included and the config has a lot of additional named arguments)
5. Start AflCrashAnalyzer.py with python 2.7

A couple of notes: 
- If AFL binaries are not /usr/local/bin, configure the path as a named argument to CrashAnalysisConfig
- The target binary is started as: /opt/binary-instrumented args_before input-file args_after, no stdin supported at the moment (sorry for that, will do as soon as I get crashes for the first stdin target)
- You might want to update the code for all your binaries to the newest developer version before compilation (even if you fuzzed on older version), so you filter out crashes that were fixed by the maintainer in the meantime. Check testcases folder (install.sh) for examples.
- You *do* want to run "peruvian were rabbit" on all your crashes (I guess at least one cycle) *before* you feed it into this program. That will help you a lot to determine exploitability.
- afl instrumented binary is the minimum, recommend is to also set at least one of the following binaries
- target_binary_plain (non-instrumented, with symbols, no ASAN)
- target_binary_asan (non-instrumented, with symbols, with ASAN)
- To get line numbers for files when running gdb, use clang's ASAN and specify ASAN_SYMBOLIZER_PATH (env configuration option, see AflCrashAnalyzer.py), see https://code.google.com/p/address-sanitizer/wiki/Flags
- When you configure the gdb script, DON'T add the "run" command at the beginning and the "quit" command at the end
- Again: Don't fully rely on the results of the exploitable gdb plugin. It lies.
- The main python file has code that shows how *I* like to run stuff, maybe you have other preferences
- Just because you get minimized crash files out of this it doesn't mean you shouldn't check their original version. You might judge differently about their exploitability.

Bugs and todo's:
- see "TODO" in code

License:
- GPL version 3  
