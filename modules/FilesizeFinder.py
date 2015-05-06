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

class FilesizeFinder:
    def __init__(self, config):
        self.config = config
    
    def files_by_file_size(self, dirname, largest_to_smallest=False):
        filepaths = []
        for path, _, files in os.walk(dirname):
            for filename in files:
                if filename.endswith(self.config.run_extension):
                    continue
                filepath = os.path.join(path, filename)
                filesize = os.stat(filepath).st_size
                filepaths.append((path, filename, filesize))
        # Sort list by file size
        # If reverse=True sort from largest to smallest
        # If reverse=False sort from smallest to largest
        filepaths.sort(key=lambda f: f[2], reverse=largest_to_smallest)
        return filepaths
    

    def rename_by_file_size(self, dirname, largest_to_smallest=False, keep_old_file=False, target=None):
        new_name = "%"+self.config.max_digets+"d" % 1
        for path, filename, _ in self.files_by_file_size(dirname, largest_to_smallest=largest_to_smallest):
            if target:
                new_name_path = target+os.path.sep+new_name
            else:
                #default: write it into the same directory where the input file lived 
                new_name_path = path+os.path.sep+new_name
            if keep_old_file:
                shutil.copyfile(path+os.path.sep+filename, new_name_path)
            else:
                shutil.move(path+os.path.sep+filename, new_name_path)
            new_name = "%"+self.config.max_digets+"d" % (int(new_name)+1)
    
