#!/usr/bin/env python2.7
'''
    AFL crash analyzer, crash triage for the American Fuzzy Lop fuzzer
    Copyright (C) 2015  floyd

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Created on Apr 13, 2015
@author: floyd, http://floyd.ch, @floyd_ch
'''

from modules.CrashAnalysisConfig import CrashAnalysisConfig
from modules.FileDuplicateFinder import FileDuplicateFinder
from modules.SignalFinder import SignalFinder
from modules.OutputFinder import OutputFinder
from modules.InputMinimizer import InputMinimizer
from utilities.Logger import Logger
import os
import glob


def get_output_for_signals(config, signal_finder, signals):
    wildcard_for_run_output_files = signal_finder.output_dir + "/*/*"+config.run_extension
    if glob.glob(wildcard_for_run_output_files):
        Logger.warning("Seems like there are already results from running the binaries, skipping. Remove output directory or run this command if you want to rerun:")
        Logger.warning("rm ", wildcard_for_run_output_files)
    else:
        Logger.info("We analyze only a couple of signals like SIGABRT, SIGSEGV, but do not care about the rest. Going for", signals)
        for signal in signals:
            Logger.info("Processing folder for output generation for signal %i" % signal)
            signal_folder = signal_finder.get_folder_path_for_signal(signal)
            if os.path.exists(signal_folder):
                Logger.info("Getting stdout and stderr of runs which result in %i. Additionally running with gdb script." % signal)
                of = OutputFinder(config, signal_folder)
                if config.target_binary_plain is None and config.target_binary_asan is None:
                    Logger.warning("You didn't specify any non-instrumented binary, running tests with instrumented binaries")
                    of.instrumented_combined_stdout_stderr()
                    of.instrumented_combined_stdout_stderr(gdb_run=True)
                else:
                    Logger.info("Plain run for", signal_folder)
                    of.plain_combined_stdout_stderr()
                    Logger.info("Plain gdb run for", signal_folder)
                    of.plain_combined_stdout_stderr(gdb_run=True)
                    Logger.info("ASAN run for", signal_folder)
                    of.asan_combined_stdout_stderr()
                    #Logger.info("ASAN gdb run for", signal_folder)
                    #of.asan_combined_stdout_stderr(gdb_run=True)
            else:
                Logger.warning("Seems that none of the crashes results in a %i signal" % signal)

def main():
    #Read the README before you start.
    
    Logger.info("Setting up configuration")

    gdb_script_64bit = r"""printf "[+] Disabling verbose and complaints\n"
set verbose off
set complaints 0
printf "[+] Backtrace:\n"
bt
printf "[+] info reg:\n"
info reg
printf "[+] exploitable:\n"
exploitable
printf "[+] disassemble $rip, $rip+16:\n"
disassemble $rip, $rip+16
"""
    gdb_script_32bit = r"""printf "[+] Disabling verbose and complaints\n"
set verbose off
set complaints 0
printf "[+] Backtrace:\n"
bt
printf "[+] info reg:\n"
info reg
printf "[+] exploitable:\n"
exploitable
printf "[+] disassemble $eip, $eip+16:\n"
disassemble $eip, $eip+16
"""
    where_this_python_script_lives = os.path.dirname(os.path.realpath(__file__))
    
    gdb_command = "gdb"
    gdb_command_osx = "/opt/local/bin/gdb-apple"
    
    config_gm = CrashAnalysisConfig(where_this_python_script_lives, 
                            target_binary_instrumented=where_this_python_script_lives+"/test-cases/gm/graphicsmagick-afl/utilities/gm", 
                            args_before="identify", 
                            args_after="", 
                            target_binary_plain=where_this_python_script_lives+"/test-cases/gm/graphicsmagick-plain/utilities/gm", 
                            target_binary_asan=where_this_python_script_lives+"/test-cases/gm/graphicsmagick-asan/utilities/gm",
                            env={"ASAN_SYMBOLIZER_PATH": "/usr/bin/llvm-symbolizer-3.4", "ASAN_OPTIONS": "symbolize=1:redzone=512:quarantine_size=512Mb:exitcode=1"},
                            crash_dir=where_this_python_script_lives+"/test-cases/gm/crashes",
                            gdb_script=gdb_script_32bit,
                            gdb_binary=gdb_command
                            )
    
#    config_ffmpeg = CrashAnalysisConfig(where_this_python_script_lives, 
#                        target_binary_instrumented=where_this_python_script_lives+"/test-cases/ffmpeg/ffmpeg-afl/ffmpeg", 
#                        args_before="-i", 
#                        args_after="-loglevel quiet", 
#                        target_binary_plain=where_this_python_script_lives+"/test-cases/ffmpeg/ffmpeg-plain/ffmpeg", 
##                        target_binary_asan=where_this_python_script_lives+"/test-cases/ffmpeg/ffmpeg-asan/ffmpeg",
#                        env={"ASAN_SYMBOLIZER_PATH": "/usr/bin/llvm-symbolizer-3.4", "ASAN_OPTIONS": "symbolize=1:redzone=512:quarantine_size=512Mb:exitcode=1"},
#                        crash_dir=where_this_python_script_lives+"/test-cases/ffmpeg/crashes",
#                        gdb_script=gdb_script_32bit,
#                        gdb_binary=gdb_command
#                        )

    #
    Logger.info("Input crashes directory operations")
    #
    
    Logger.info("Removing README.txt files")
    fdf = FileDuplicateFinder(config_gm)
    fdf.remove_readmes(config_gm.original_crashes_directory)
    
    Logger.info("Removing duplicates from original crashes folder (same file size + MD5)")
    fdf.delete_duplicates_recursively(config_gm.original_crashes_directory)
    
    Logger.info("Renaming files from original crashes folder so that the filename is a unique identifier. This allows us to copy all crash files into one directory (eg. for tmin output) if necessary, without name collisions")
    fdf.rename_same_name_files(config_gm.original_crashes_directory)
    
    #
    Logger.info("Finding signals for all crash files")
    #
    sf = SignalFinder(config_gm)
    if os.path.exists(sf.output_dir):
        Logger.warning("Seems like all crashes were already categorized by signal, skipping. Remove output directory or remove this folder if you want to rerun:", sf.output_dir)
    else:
        Logger.info("Dividing files to output folder according to their signal")
        os.mkdir(sf.output_dir)
        sf.divide_by_signal(0)
        
    
    #
    Logger.info("Running binaries to discover stdout/stderr, gdb and ASAN output for crash files that result in interesting signals")
    #
    #signals, negative on OSX, 129 and above for Linux. No harm if we go on with all of them.
    signals = (-4, -6, -11, 132, 134, 139)
    get_output_for_signals(config_gm, sf, signals)

    
    #
    Logger.info("Minimizing input files that result in interesting signals (and removing duplicates from the results)")
    #
    im = InputMinimizer(config_gm)
    if os.path.exists(im.output_dir):
        Logger.warning("Seems like minimized crashes were already categorized by signal, skipping. Remove output directory or remove this folder if you want to rerun:", im.output_dir)
    else:
        os.mkdir(im.output_dir)
        for signal in signals:
            Logger.info("Processing minimized folder for crash-minimizer for signal %i" % signal)
            signal_folder = sf.get_folder_path_for_signal(signal)
            im = InputMinimizer(config_gm, signal_folder)
            if os.path.exists(signal_folder):
                Logger.info("Minimizing inputs resulting in signal %i" % signal)
                im.minimize_testcases()
            else:
                Logger.warning("Seems that none of the crashes results in a %i signal" % signal)
        Logger.info("Removing duplicates from minimized tests")
        fdf.delete_duplicates_recursively(im.output_dir)
        
    #
    Logger.info("Finding signals for minimized crash files")
    #
    sf_minimized_crashes = SignalFinder(config_gm, im.output_dir, os.path.join(config_gm.output_dir, "minimized-inputs-per-signal"))
    if os.path.exists(sf_minimized_crashes.output_dir):
        Logger.warning("Seems like crashes were already categorized by signal, skipping.")
        Logger.warning("Remove output directory or remove this folder if you want to rerun:", sf_minimized_crashes.output_dir)
    else:
        os.mkdir(sf_minimized_crashes.output_dir)
        Logger.info("Dividing files to output folder according to their signal")
        sf_minimized_crashes.divide_by_signal(0)
        
    
    #
    Logger.info("Running binaries to discover stdout/stderr, gdb and ASAN output for minimized input files that result in interesting signals")
    #
    get_output_for_signals(config_gm, sf_minimized_crashes, signals)
    
    
    #
    # Analyze exploitability
    #
    #egp = ExploitableGdbPlugin(config_gm)
#TODO: develop further
#- peruvian were rabbit?
#- exploitable script, something along: less `grep -l 'Exploitability Classification: EXPLOITABLE' output/per-signal/*/*gdb*`

    
if __name__ == "__main__":
    main()




