#COMPILER_C=gcc
#COMPILER_CPP=g++
COMPILER_C=clang
COMPILER_CPP=clang++

#Note: There are more disc space efficient ways, make sure you have enough disc space

if [ ! -d ./ffmpeg-plain ]; then
    sudo apt-get install git yasm
    git clone git://source.ffmpeg.org/ffmpeg.git ffmpeg-plain
    cp -r ffmpeg-plain ffmpeg-afl
    cp -r ffmpeg-plain ffmpeg-asan
fi

echo "[+] Updating ffmpeg-plain"
cd ffmpeg-plain
git pull
cd ..
echo "[+] Updating ffmpeg-afl"
cd ffmpeg-afl
git pull
cd ..
echo "[+] Updating ffmpeg-asan"
cd ffmpeg-asan
git pull
cd ..

echo "[+] Compiling ffmpeg-plain"
cd ffmpeg-plain
export CFLAGS="-Wall -g" && export CC=$COMPILER_C && export CXX=$COMPILER_CPP && ./configure --disable-pthreads --disable-ffplay --disable-ffprobe --disable-ffserver --disable-doc --disable-stripping --disable-shared --cc=$COMPILER_C --cxx=$COMPILER_CPP && make clean && make 
cd ..

echo "[+] Compiling ffmpeg-afl"
cd ffmpeg-afl
export CFLAGS="-Wall -g" && export CC=afl-$COMPILER_C && export CXX=afl-$COMPILER_CPP && ./configure --disable-pthreads --disable-ffplay --disable-ffprobe --disable-ffserver --disable-doc --disable-shared --cc=afl-$COMPILER_C --cxx=afl-$COMPILER_CPP && make clean && make 
cd ..

echo "[+] Compiling ffmpeg-asan"
cd ffmpeg-asan
#Usually we would set -fstack-protector-all as well, but ffmpeg's configure will complain that the compiler is not able to produce binaries
#This is only true when ASAN and -fstack-protector-all is used (each individually is fine)
#Additionally (separate issue): had issues with ASAN on ARM:
#/usr/bin/ld.bfd.real: cannot find /usr/bin/../lib/clang/3.4/lib/linux/libclang_rt.asan-arm.a: No such file or directory
#too lazy to debug, didn't build with ASAN on ARM
export CFLAGS="-Wall -g -fsanitize=address -fno-omit-frame-pointer" && export CC=$COMPILER_C && export CXX=$COMPILER_CPP && ./configure --disable-pthreads --disable-ffplay --disable-ffprobe --disable-ffserver --disable-doc --disable-stripping --disable-shared --cc=$COMPILER_C --cxx=$COMPILER_CPP && make clean && make 
cd ..

