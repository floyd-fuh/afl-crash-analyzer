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
import shutil
from utilities.Executer import Executer
from utilities.Logger import Logger

class SignalFinder:
    
    TIMEOUT_SIGNAL=9998
    VARYING_SIGNAL=9999
    
    def __init__(self, config, search_dir=None, output_dir=None):
        self.config = config
        self.search_dir = search_dir
        if self.search_dir is None:
            self.search_dir = self.config.original_crashes_directory
        self.output_dir = output_dir
        if self.output_dir is None:
            self.output_dir = self.config.default_signal_directory
        if config.target_binary_plain:
            Logger.debug("Using", self.config.target_binary_plain, "for signal run")
            self.binary_to_use = self.config.target_binary_plain
        elif config.target_binary_asan:
            Logger.debug("Using", self.config.target_binary_asan, "for signal run")
            self.binary_to_use = self.config.target_binary_asan
        else:
            Logger.debug("Using", self.config.target_binary_instrumented, "for signal run")
            self.binary_to_use = self.config.target_binary_instrumented
    
    
    def divide_by_signal(self, confirmation_loops=0, function=shutil.copyfile):
        if self.output_dir is not None and not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        ex = Executer(self.config)
        for path, _, files in os.walk(self.search_dir):
            for filename in files:
                if filename.endswith(self.config.run_extension):
                    continue
                filepath = os.path.join( path, filename )
                command = self.config.get_command_line(self.binary_to_use, filepath)
                Logger.debug("Executing:", command, debug_level=4)
                Logger.busy()
                signal = ex.get_signal_for_run(command, env=self.config.env)
                while confirmation_loops > 0:
                    Logger.busy()
                    new_signal = ex.get_signal_for_run(command, env=self.config.env)
                    if new_signal == signal:
                        signal = new_signal
                        confirmation_loops -= 1
                    else:
                        Logger.info("Detected varying return codes for exactly the same run")
                        signal = SignalFinder.VARYING_SIGNAL
                        break
                Logger.debug("We consider signal %i for input file %s" % (signal, filename), debug_level=5)
                destination_dir = self.get_folder_path_for_signal(signal)
                if not os.path.exists(destination_dir):
                    os.mkdir(destination_dir)
                function(filepath, os.path.join(destination_dir, filename))
    
    def get_folder_path_for_signal(self, signal):
        signal_folder_name = str(signal)
        return os.path.join(self.output_dir, signal_folder_name)

    def get_folder_paths_for_signals_if_exist(self, ignore_signals):
        l = list(set(range(-500,500)) - set(ignore_signals))
        l.sort()
        for signal in l:
            signal_folder = self.get_folder_path_for_signal(signal)
            if os.path.exists(signal_folder):
                yield signal, signal_folder
        