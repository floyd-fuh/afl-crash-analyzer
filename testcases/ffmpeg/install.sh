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

#Helps for ARM: https://www.bitpi.co/2015/08/19/how-to-compile-ffmpeg-on-a-raspberry-pi/

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
#On ARM on 23. April 2016 git it worked with: 
#export CFLAGS="" && export LDFLAGS="-lpthread" && export CC=afl-clang && export CXX=afl-clang++ && ./configure --disable-pthreads --disable-ffplay --disable-ffprobe --disable-ffserver --disable-doc --disable-shared --cc=afl-clang --cxx=afl-clang++ --disable-asm && make
cd ffmpeg-afl
export CFLAGS="-Wall -g" && export CC=afl-$COMPILER_C && export CXX=afl-$COMPILER_CPP && ./configure --disable-pthreads --disable-ffplay --disable-ffprobe --disable-ffserver --disable-doc --disable-shared --cc=afl-$COMPILER_C --cxx=afl-$COMPILER_CPP && make clean && AFL_INST_RATIO=30 make 
cd ..

echo "[+] Compiling ffmpeg-asan"
cd ffmpeg-asan
#This was a torture to get this running, several issues here:
#On x86 on older versions we had to remove -fstack-protector-all as ffmpeg's configure will complain that the compiler is not able to produce binaries, but seems fixed now
#Then I ran into an issue that is a problem in a lot of programs when you try to use a sanitizer: https://savannah.gnu.org/patch/?8775
#It won't build with ASAN when inline assembly is enabled...
#Additionally the LDFLAGS with lpthread are necessary even when you specify --disable-pthreads... well I guess there is somewhere an unconditional import
#Additionally (separate issue): had issues with ASAN on ARM:
#/usr/bin/ld.bfd.real: cannot find /usr/bin/../lib/clang/3.4/lib/linux/libclang_rt.asan-arm.a: No such file or directory
#too lazy to debug, didn't build with ASAN on ARM
export LDFLAGS="-lpthread -fsanitize=address" export CFLAGS="-Wall -g -fsanitize=address -fno-omit-frame-pointer -fstack-protector-all" && export CC=$COMPILER_C && export CXX=$COMPILER_CPP && ./configure --disable-pthreads --disable-ffplay --disable-ffprobe --disable-ffserver --disable-doc --disable-stripping --disable-shared --cc=$COMPILER_C --cxx=$COMPILER_CPP --disable-inline-asm && make clean && make
cd ..

