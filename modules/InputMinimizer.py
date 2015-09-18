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
from modules.SignalFinder import SignalFinder
import os

class InputMinimizer:
    def __init__(self, config, search_dir=None, output_dir=None):
        self.config = config
        self.search_dir = search_dir
        if self.search_dir is None:
            self.search_dir = self.config.original_crashes_directory
        self.output_dir = output_dir
        if self.output_dir is None:
            self.output_dir = self.config.default_minimized_crashes_directory
    
    def minimize_testcases(self):
        if self.output_dir is not None and not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        executer = Executer(self.config)
        for path, _, files in os.walk(self.search_dir):
            for filename in files:
                if filename.endswith(self.config.run_extension):
                    continue
                Logger.info("Minimizing", filename)
                filepath = os.path.join(path, filename)
                cmd = self.config.get_afl_tmin_command_line(filepath, os.path.join(self.output_dir, filename))
                Logger.debug("Executing:", cmd)
                Logger.busy()
                signal = executer.get_signal_for_run(cmd, self.config.run_timeout_tmin, env=self.config.env)
                if signal == SignalFinder.TIMEOUT_SIGNAL:
                    Logger.error("Minimizing this file took too long, aborted")
