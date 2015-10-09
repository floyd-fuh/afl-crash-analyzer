#COMPILER_C=gcc
#COMPILER_CPP=g++
COMPILER_C=clang
COMPILER_CPP=clang++

#Note: There are more disc space efficient ways, make sure you have enough disc space

if [ ! -d ./graphicsmagick-plain ]; then
    sudo apt-get install mercurial
    hg clone http://hg.code.sf.net/p/graphicsmagick/code graphicsmagick-plain
    cp -r graphicsmagick-plain graphicsmagick-afl
    cp -r graphicsmagick-plain graphicsmagick-asan
fi

echo "[+] Updating graphicsmagick-plain"
cd graphicsmagick-plain
hg pull
hg update
cd ..
echo "[+] Updating graphicsmagick-afl"
cd graphicsmagick-afl
hg pull
hg update
cd ..
echo "[+] Updating graphicsmagick-asan"
cd graphicsmagick-asan
hg pull
hg update
cd ..

echo "[+] Compiling graphicsmagick-plain"
cd graphicsmagick-plain
export CFLAGS="-Wall -g" && export CC=$COMPILER_C && export CXX=$COMPILER_CPP && ./configure --disable-shared && make clean && make 
cd ..

echo "[+] Compiling graphicsmagick-afl"
cd graphicsmagick-afl
export CFLAGS="-Wall -g" && export CC=afl-$COMPILER_C && export CXX=afl-$COMPILER_CPP && ./configure --disable-shared && make clean && make 
cd ..

echo "[+] Compiling graphicsmagick-asan"
cd graphicsmagick-asan
#We're setting -fstack-protector-all as well
#Attention: had issues with ASAN on ARM: checking whether the C compiler works... no
#too lazy to debug, didn't build with ASAN on ARM
export CFLAGS="-Wall -g -fstack-protector-all -fsanitize=address -fno-omit-frame-pointer" && export CC=$COMPILER_C && export CXX=$COMPILER_CPP && ./configure --disable-shared && make clean && make 
cd ..

