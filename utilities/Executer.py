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
import subprocess
import multiprocessing
import Queue

class Executer:
    #TODO: more jailing of processes, so that they don't go rampage and use up all memory and such things (especially on OSX)
    #TODO: Migrate to python 3, there is a nice timeout argument for subprocess.call
    def __init__(self, config):
        self.config = config
        self.pipe = subprocess.PIPE
    
    def get_signal_for_run(self, command, timeout=None, env={}):
        if not timeout:
            timeout = self.config.run_timeout
        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=self._get_signal_for_run, args=(q, command, env))
        p.start()
        #TODO: get rid of magic number
        signal = 9998
        try:
            #blocking call:
            signal = q.get(True, timeout) 
        except Queue.Empty, Queue.Full:
            pass
        p.join(1)
        return signal

    
    def _get_signal_for_run(self, q, command, env={}):
        #TODO: make stdout / stderr configurable
        process = subprocess.Popen(command, stdin=None, shell=True, stdout=file("/dev/null"), stderr=file("/dev/null"))
        process.communicate()
        signal = process.returncode
        q.put(signal)
    
    
    def get_output_for_run(self, command, stdout, timeout=None, env={}, stderr=subprocess.STDOUT):
        output = None
        if not timeout:
            timeout = self.config.run_timeout
        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=self._get_output_for_run, args=(q, command, stdout, stderr, env))
        p.start()
        try:
            #blocking call:
            output = q.get(True, timeout) 
        except Queue.Empty, Queue.Full:
            pass
        p.join(1)
        return output
    
    def _get_output_for_run(self, q, command, stdout, stderr, env={}):
        #TODO: add support for stdin
        process = subprocess.Popen(command, stdin=None, stdout=stdout, stderr=stderr, shell=True)
        out, err = process.communicate()
        #errcode = process.returncode
        q.put(out)