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
from utilities.Logger import Logger
from utilities.Executer import Executer
from utilities.OutputUtility import get_new_output_file_name
import os

class OutputFinder:
    def __init__(self, config, search_dir=None, output_dir=None):
        self.config = config
        self.search_dir = search_dir
        if self.search_dir is None:
            self.search_dir = self.config.original_crashes_directory
        #output directory will be just the same place where the input file is if output_dir is None
        self.output_dir = output_dir
    
    def do_sane_output_runs(self):
        if self.output_dir is not None and not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        if self.config.target_binary_plain is None and self.config.target_binary_asan is None:
            Logger.warning("You didn't specify any non-instrumented binary, running tests with instrumented binaries")
            self.instrumented_combined_stdout_stderr()
            self.instrumented_combined_stdout_stderr(gdb_run=True)
        else:
            Logger.info("Plain run")
            self.plain_combined_stdout_stderr()
            Logger.info("Plain gdb run")
            self.plain_combined_stdout_stderr(gdb_run=True)
            Logger.info("ASAN run")
            self.asan_combined_stdout_stderr()
            #I don't know why we should run this:
            #Logger.info("ASAN gdb run")
            #self.asan_combined_stdout_stderr(gdb_run=True)
    
    
    def instrumented_combined_stdout_stderr(self, gdb_run=False):
        self._combined_stdout_stderr(self.config.target_binary_instrumented, gdb_run, self.config.output_prefix_instrumented)
    
    def plain_combined_stdout_stderr(self, gdb_run=False):
        if not self.config.target_binary_plain:
            Logger.warning("You didn't configure a plain binary (recommended: with symbols), therefore skipping run with plain binary.")
        else:
            self._combined_stdout_stderr(self.config.target_binary_plain, gdb_run, self.config.output_prefix_plain)

    def asan_combined_stdout_stderr(self, gdb_run=False):
        if not self.config.target_binary_asan:
            Logger.warning("You didn't configure an ASAN enabled binary (recommended: with symbols), therefore skipping run with ASAN binary.")
        else:
            self._combined_stdout_stderr(self.config.target_binary_asan, gdb_run, self.config.output_prefix_asan)
    
    
    def _combined_stdout_stderr(self, binary, gdb_run, hint):
        executer = Executer(self.config)
        for path, _, files in os.walk(self.search_dir):
            for filename in files:
                if filename.endswith(self.config.run_extension):
                    continue
                filepath = os.path.join(path, filename)
                if gdb_run:
                    command = self.config.get_gdb_command_line(binary, filepath)
                    new_filename = filename+"-"+os.path.basename(binary)+hint+self.config.gdb_prefix
                else:
                    command = self.config.get_command_line(binary, filepath)
                    new_filename = filename+"-"+os.path.basename(binary)+hint
                Logger.debug("Looking for stdout/stderr output:", command, debug_level=4)
                if self.output_dir:
                    output_file_name = get_new_output_file_name(self.output_dir, new_filename, self.config.run_extension, self.config.max_digets)
                    new_filepath = os.path.join(self.output_dir, output_file_name)
                else:
                    output_file_name = get_new_output_file_name(path, new_filename, self.config.run_extension, self.config.max_digets)
                    new_filepath = os.path.join(path, output_file_name)
                fp = file(new_filepath, "w")
                Logger.busy()
                executer.get_output_for_run(command, fp, env=self.config.env)
                fp.close()
        
