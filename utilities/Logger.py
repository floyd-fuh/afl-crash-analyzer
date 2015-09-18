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
import sys
class Logger():
    #TODO: use curses, use colors, etc.
    debugging_on = True
    debug_level = 4
    busy_inform = not debugging_on or debug_level <= 3
    @staticmethod
    def setDebug(level):
        Logger.debug_level = level
    @staticmethod
    def error(*text):
        print "[-] Error: "+str(" ".join(str(i) for i in text)) 
    @staticmethod
    def warning(*text):
        print " [-] Warning: "+str(" ".join(str(i) for i in text)) 
    @staticmethod
    def fatal(*text):
        print "[-] Fatal Error: "+str(" ".join(str(i) for i in text))
        exit()
    @staticmethod
    def info(*text):
        print "[+] "+str(" ".join(str(i) for i in text))
    @staticmethod
    def debug(*text, **kwargs):
        level = 2
        if "debug_level" in kwargs:
            level = kwargs["debug_level"]
        if level <= Logger.debug_level:
            print "  ["+"+"*level+"] "+str(" ".join(str(i) for i in text))
    @staticmethod
    def busy():
        if Logger.busy_inform:
            sys.stdout.write(".")