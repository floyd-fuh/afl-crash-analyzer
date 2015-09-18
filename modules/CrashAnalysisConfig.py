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
import os
from utilities.Logger import Logger
from utilities.OutputUtility import get_new_output_file_name


class CrashAnalysisConfig:
    def __init__(self, main_dir, target_binary_instrumented, args_before, args_after, 
                 target_binary_plain=None, target_binary_asan=None, max_digets=4,
                 env={}, crash_dir=None, output_dir=None, gdb_script=None, gdb_binary="gdb", 
                 run_timeout=15, tmin_args="", is_stdin_binary=False):
        
        #Main directory where these scripts live, all other directories will be derived relatively from here
        self.main_dir = main_dir
        
        #Where you stored the crash files AFL produced
        if crash_dir is None:
            self.original_crashes_directory = os.path.join(self.main_dir, "crashes")
        else:
            self.original_crashes_directory = crash_dir
        
        #Where we will store the output of all the stuff we run.
        if output_dir is None:
            self.output_dir = os.path.join(self.main_dir, "output")
        else:
            self.output_dir = output_dir
        
        #a tmp directory, where they should put it:
        self.tmp_dir = os.path.join(self.output_dir, "tmp")
        
        #When we categorize crashes by signals and no directory for output is given, this one will be used
        self.default_signal_directory = os.path.join(self.output_dir, "per-signal")
        
        #When we minimize crashes and no directory for output is given, this one will be used
        self.default_minimized_crashes_directory = os.path.join(self.output_dir, "minimized-inputs")
        
        #Make sure this binary is instrumented (meaning compiled with afl-gcc or afl-clang), so that it can be used
        #with afl binaries (eg. afl-tmin). This is the "minimum" target binary you need.
        #Full path necessary
        self.target_binary_instrumented = target_binary_instrumented
        
        #After finding crashes, we want to categorize crashes without any involvement of AFL.
        #Only use the instrumented binary if you are 100% sure the AFL compilation didn't introduce any bugs.
        #So best would be if this is a regular gcc compile, WITH symbols BUT WITHOUT ASAN, just clean.
        #For example the binary from your OS repository
        #If you don't have such a binary, leave it as None
        #Full path necessary
        self.target_binary_plain = target_binary_plain
        
        #Same as target_binary_plain but with ASAN enabled
        #If you don't have such a binary, leave it as None
        #Full path necessary
        self.target_binary_asan = target_binary_asan
        
        #Any arguments for binary which should be put in front of the input file parameter @@
        self.args_before = args_before
        
        #Any arguments for binary which should be put after the input file parameter @@
        self.args_after = args_after
        
        #How many digets, especially for file names. For example 6 means file will be named 000001 to 999999
        #and the scripts will crash if you have more than 999999 files
        self.max_digets = max_digets
        
        #usually output filess have naming convention: fileName-binaryName-outputPrefix-gdbPrefix-runExtension
        #Prefixes for binary type
        self.output_prefix_plain = "-plain"
        self.output_prefix_instrumented = "-instrumented"
        self.output_prefix_asan = "-asan"
        #Prefix if run with gdb
        self.gdb_prefix = "-gdb"
        #The file extension for *ALL* output files (for runs, eg. stdout/stderr or with gdb)
        self.run_extension = "_run.txt"
        
        #environment variables used whenever anything is executed in a shell
        self.env = env
        
        #gdb script
        self.gdb_script = gdb_script
        
        #where we write the gdb script to disc
        self.gdb_script_path = os.path.join(self.tmp_dir, "gdb_script.txt")
        self.gdb_binary = gdb_binary
        self.gdb_args = "-q --batch"
        
        #tmin args
        self.tmin_args = tmin_args
        
        #How long we execute binaries until we kill them. This is for a "regular" run with an input file in seconds
        self.run_timeout = run_timeout
        
        #How long we run afl-tmin on one input file until we kill it in seconds
        self.run_timeout_tmin = 15*60
        
        #True if this binary is not reading from a file but is reading stdin
        self.is_stdin_binary = is_stdin_binary
        
    
    def sanity_check(self):
        ##
        # Sanity checks and initial setup
        ##
        if not os.access(self.target_binary_instrumented, os.R_OK):
            Logger.fatal("AFL target binary not accessible:", self.target_binary_instrumented+". Did you configure the CrashAnalysisConfig class?")
        if not self.target_binary_plain is None and not os.access(self.target_binary_plain, os.R_OK):
            Logger.fatal("Target binary not accessible:", self.target_binary_plain+". Did you configure the CrashAnalysisConfig class?")
        if not self.target_binary_asan is None and not os.access(self.target_binary_asan, os.R_OK):
            Logger.fatal("ASAN target binary not accessible:", self.target_binary_asan+". Did you configure the CrashAnalysisConfig class?")
        if not os.access(self.main_dir, os.F_OK):
            Logger.fatal("Your main_dir doesn't exist:", self.main_dir)
        if not os.access(self.original_crashes_directory, os.F_OK):
            Logger.fatal("Your original_crashes_directory doesn't exist:", self.original_crashes_directory)

        if os.path.exists(self.output_dir):
            Logger.warning("Your output directory already exists, did you want to move it before running?", self.output_dir)
        else:
            Logger.info("Output folder will be:", self.output_dir)
            os.mkdir(self.output_dir)
        if not os.path.exists(self.tmp_dir):
            os.mkdir(self.tmp_dir)
        self.prepare_gdb_script()
        
    def prepare_gdb_script(self, new_gdb_script=None):
        if new_gdb_script is None:
            new_gdb_script = self.gdb_script
            output_file_path = self.gdb_script_path
        else:
            output_file_path = os.path.join(self.tmp_dir, get_new_output_file_name(self.tmp_dir, "gdb_script", ".txt", self.max_digets))
        #TODO: support stdin
        script_content = 'run' + os.linesep
        script_content += new_gdb_script + os.linesep
        script_content += "quit"
        file(output_file_path, "w").write(script_content)
        return output_file_path

    def get_command_line(self, binary, filepath):
        command = '"'+binary+'"'
        if self.args_before:
            command += " "+self.args_before
        if filepath: #TODO: support stdin
            command += ' "'+filepath+'"'
        if self.args_after:
            command += " "+self.args_after
        return command
    
    def get_gdb_command_line(self, binary, filepath, path_to_gdb_script=None):
        if path_to_gdb_script is None:
            path_to_gdb_script = self.gdb_script_path
        command = self.gdb_binary
        if self.gdb_args:
            command += ' '+self.gdb_args
        command += ' --command="'+path_to_gdb_script+'"'
        command += ' --args '+self.get_command_line(binary, filepath)
        return command

    def get_afl_tmin_command_line(self, input_filepath, output_filepath):
        command = "afl-tmin"
        if self.tmin_args:
            command += ' '+self.tmin_args
        command += ' -i "'+input_filepath+'"'
        command += ' -o "'+output_filepath+'"'
        if self.is_stdin_binary:
            command += ' '+self.get_command_line(self.target_binary_instrumented, "")
        else:
            command += ' '+self.get_command_line(self.target_binary_instrumented, "@@")
        return command
    
    def get_most_standard_binary(self):
        if self.target_binary_plain is not None:
            return self.target_binary_plain
        elif self.target_binary_asan is not None:
            return self.target_binary_asan
        elif self.target_binary_instrumented is not None:
            return self.target_binary_instrumented
    
    def get_gdb_exploitable_file_extension(self):
        #I guess there is no point in running the "exploitable" gdb plugin over an ASAN binary
        if self.target_binary_plain:
            return "-"+os.path.basename(self.target_binary_plain)+self.output_prefix_plain+self.gdb_prefix+self.run_extension
        else:
            return "-"+os.path.basename(self.target_binary_instrumented)+self.output_prefix_instrumented+self.gdb_prefix+self.run_extension