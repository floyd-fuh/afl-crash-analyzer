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
import signal
import multiprocessing
import Queue
from utilities.Logger import Logger

class Executer:
    #TODO: more jailing of processes, so that they don't go rampage and use up all memory and such things (especially on OSX)
    #What we are doing here: http://stackoverflow.com/questions/4033578/how-to-limit-programs-execution-time-when-using-subprocess
    #We send a timeout as SIGALRM and when it is reached we simply kill the process.
    def __init__(self, config):
        self.TIMEOUT_SIGNAL = 9998
        self.config = config
        self.current_process = None
        self.timeout_flag = False
        self.sigttou_flag = False
        
    def _handle_alarm(self, signum, frame):
        # If the alarm is triggered, we're still in the communicate()
        # call, so use kill() to end the process
        self.timeout_flag = True
        try:
            self.current_process.kill()
        except OSError as ose:
            Logger.info("Kill failed. Sometimes the process exactly exits before we try to kill it... coward. Nothing to worry about.", ose)
    
    def _handle_sigttou(self, signum, frame):
        #Had some issues that when memory corruptions occured in a subprocess
        #(no matter if shielded by multiprocess and subprocess module), 
        #that a SIGTTOU was sent to the entire Python main process.
        #According to https://en.wikipedia.org/wiki/SIGTTOU this
        #results in the process being stopped (and it looks like SIGSTP on the cmd):
        #[1]+  Stopped                 ./AflCrashAnalyzer.py
        #Of course we don't want that. Debugging was hard but then
        #realized after this program was stopped:
        #$ echo $?
        #150
        #So that's SIGTTOU on Linux at least.
        #This handler will prevent the process to stop.
        self.sigttou_flag = True
        try:
            self.current_process.kill()
        except OSError as ose:
            Logger.info("Kill failed. Sometimes the process exactly exits before we try to kill it... coward. Nothing to worry about.", ose)

    
    def run_command(self, command, timeout=None, env={}, stdout=file("/dev/null"), stderr=file("/dev/null")):
        #TODO: make stdout / stderr configurable
        if not timeout:
            timeout = self.config.run_timeout
        process = subprocess.Popen(command, stdin=None, shell=False, stdout=stdout, stderr=stderr)
        self.current_process = process
        signal.signal(signal.SIGALRM, self._handle_alarm)
        #We also had a problem that memory corruptions...
        signal.signal(signal.SIGTTOU, self._handle_sigttou)
        signal.alarm(timeout)
        self.timeout_flag = False
        self.sigttou_flag = False
        #TODO: get rid of magic number
        ret_signal = self.TIMEOUT_SIGNAL
        #blocking call:
        process.communicate()
        signal.alarm(0)
        #This line is reached when timeout_flag was set by _handle_alarm if it was called
        if self.timeout_flag:
            Logger.debug("Process was killed as it exceeded the time limit", debug_level=3)
            ret_signal = self.TIMEOUT_SIGNAL
        elif self.sigttou_flag:
            Logger.debug("Some memory corruption resulted in a SIGTTOU signal being thrown (usually stops process). We caught it.", debug_level=3)
            ret_signal = signal.SIGTTOU
        else:
            ret_signal = process.returncode
        return ret_signal
