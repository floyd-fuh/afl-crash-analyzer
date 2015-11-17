#!/usr/local/bin/python2.7
# encoding: utf-8

from modules.CrashAnalysisConfig import CrashAnalysisConfig

def create_config(main_dir, *args, **kwargs):
    
    #TODO: fix so that ASAN version of ffmpeg compiles
    config = CrashAnalysisConfig(main_dir, 
                            target_binary_instrumented=main_dir+"/testcases/ffmpeg/ffmpeg-afl/ffmpeg", 
                            args_before=["-i"], 
                            args_after=["-loglevel", "quiet"],
                            target_binary_plain=main_dir+"/testcases/ffmpeg/ffmpeg-plain/ffmpeg", 
#                            target_binary_asan=main_dir+"/testcases/ffmpeg/ffmpeg-asan/ffmpeg",
                            crash_dir=main_dir+"/testcases/ffmpeg/crashes",
                            *args,
                            **kwargs
                            )
    return config
