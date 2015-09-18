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
from md5 import md5
from utilities.Logger import Logger

class FileDuplicateFinder:
    def __init__(self, config, search_dir):
        self.config = config
        self.search_dir = search_dir
    
    def find_duplicate_contents(self, rootdir):
        """Find duplicate files in directory tree."""
        filesizes = {}
        # Build up dict with key as filesize and value is list of filenames.
        for path, _, files in os.walk(rootdir):
            for filename in files:
                if filename.endswith(self.config.run_extension):
                    continue
                filepath = os.path.join(path, filename)
                filesize = os.stat(filepath).st_size
                filesizes.setdefault(filesize, []).append(filepath)
        # We are only interested in lists with more than one entry,
        # meaning a file can not have the same content if it has a
        # different size
        for files in [ flist for flist in filesizes.values() if len(flist)>1 ]:
            unique = set()
            for filepath in files:
                with open(filepath) as openfile:
                    filehash = md5(openfile.read()).hexdigest()
                if filehash not in unique:
                    unique.add(filehash)
                else:
                    yield filepath
        
    def delete_duplicates_recursively(self):
        Logger.info("Removing duplicates in", self.search_dir)
        for duplicate in self.find_duplicate_contents(self.search_dir):
            if duplicate.endswith(self.config.run_extension):
                continue
            Logger.info("Deleting the duplicate file:", duplicate)
            os.remove(duplicate)
    
    def remove_readmes(self):
        for path, _, files in os.walk(self.search_dir):
            for filename in files:
                if filename == "README.txt":
                    os.remove(os.path.join(path, filename))

    def rename_same_name_files(self):
        filenames = []
        for path, _, files in os.walk(self.search_dir):
            for filename in files:
                i = 1
                new_filename = filename
                name, extension = os.path.splitext(filename)
                while new_filename in filenames:
                    formatstr = "%0"+str(self.config.max_digets)+"d"
                    new_number = formatstr % i
                    new_filename = name + "_" + new_number + extension
                    i += 1
                if not new_filename == filename:
                    Logger.info("Found filename that is already taken, renaming", filename, "to", new_filename)
                    shutil.move(os.path.join(path, filename), os.path.join(path, new_filename))
                filenames.append(new_filename)
    
    def rename_all_files(self, extension=""):
        i = 1
        for path, _, files in os.walk(self.search_dir):
            for filename in files:
                formatstr = "%0"+str(self.config.max_digets+4)+"d"
                new_filename = formatstr % i
                shutil.move(os.path.join(path, filename), os.path.join(path, new_filename+extension))
                i = i+1