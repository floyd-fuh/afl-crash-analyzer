#!/usr/local/bin/python2.7
# encoding: utf-8

from modules.CrashAnalysisConfig import CrashAnalysisConfig

def create_config(main_dir, *args, **kwargs):
    config = CrashAnalysisConfig(main_dir, 
                            target_binary_instrumented=main_dir+"/testcases/gm/graphicsmagick-afl/utilities/gm", 
                            args_before=["identify"], 
                            args_after=[], 
                            target_binary_plain=main_dir+"/testcases/gm/graphicsmagick-plain/utilities/gm", 
                            target_binary_asan=main_dir+"/testcases/gm/graphicsmagick-asan/utilities/gm",
                            #just takes too long if we do all, so we only go through the "new" folder 
                            crash_dir=main_dir+"/testcases/gm/crashes/new",
                            *args,
                            **kwargs
                            )
    return config
