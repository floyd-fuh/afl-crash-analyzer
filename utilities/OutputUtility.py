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
def get_new_output_file_name(path, filename, extension, max_digets):
    new_filename = filename
    i = 1
    while os.path.exists(os.path.join(path, new_filename+extension)) and i < 10**max_digets:
        formatstr = "%0"+str(max_digets)+"d"
        new_number = formatstr % i
        new_filename = filename + new_number
        i += 1
    return new_filename + extension

def list_as_intervals(li, as_hex=False):
    li = list(set(li))
    li.sort()
    out = []
    last = li[0]
    start = last
    for x in li[1:]:
        if not x - last <= 1:
            if start == last:
                out.append(hex(start) if as_hex else str(start))
            else:
                val = hex(start) if as_hex else str(start)
                val2 = hex(last) if as_hex else str(last)
                out.append(val+"-"+str(val2))
            start = x
        last = x
    if start == last:
        out.append(hex(start) if as_hex else str(start))
    else:
        val = hex(start) if as_hex else str(start)
        val2 = hex(last) if as_hex else str(last)
        out.append(val+"-"+str(val2))
    return ", ".join(out)