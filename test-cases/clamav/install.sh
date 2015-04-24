#COMPILER_C=gcc
#COMPILER_CPP=g++
COMPILER_C=clang
COMPILER_CPP=clang++

#Note: There are more disc space efficient ways, make sure you have enough disc space

if [ ! -d ./clamav-plain ]; then
    sudo apt-get install git
    git clone https://github.com/vrtadmin/clamav-devel clamav-plain
    cp -r clamav-plain clamav-afl
    cp -r clamav-plain clamav-asan
fi

echo "[+] Updating clamav-plain"
cd clamav-plain
git pull
cd ..
echo "[+] Updating clamav-afl"
cd clamav-afl
git pull
cd ..
echo "[+] Updating clamav-asan"
cd clamav-asan
git pull
cd ..

echo "[+] Compiling clamav-plain"
cd clamav-plain
mkdir installed
export CFLAGS="-Wall -g" && export CC=$COMPILER_C && export CXX=$COMPILER_CPP && ./configure --prefix="`pwd`/installed/" && make clean && make && make install
mkdir ./installed/share/clamav
cp ./installed/etc/freshclam.conf.sample ./installed/etc/freshclam.conf
sed -i 's/Example//g' ./installed/etc/freshclam.conf
cp ./installed/etc/clamd.conf.sample ./installed/etc/clamd.conf
sed -i 's/Example//g' ./installed/etc/clamd.conf
./installed/bin/freshclam 
cd ..

echo "[+] Compiling clamav-afl"
cd clamav-afl
mkdir installed
export CFLAGS="-Wall -g" && export CC=afl-$COMPILER_C && export CXX=afl-$COMPILER_CPP && ./configure --prefix="`pwd`/installed/" && make clean && make && make install
cp ./installed/etc/freshclam.conf.sample ./installed/etc/freshclam.conf
sed -i 's/Example//g' ./installed/etc/freshclam.conf
cp ./installed/etc/clamd.conf.sample ./installed/etc/clamd.conf
sed -i 's/Example//g' ./installed/etc/clamd.conf
./installed/bin/freshclam
cd ..

echo "[+] Compiling clamav-asan"
cd clamav-asan
mkdir installed
#We're setting -fstack-protector-all as well
#Attention: had issues with ASAN on ARM:
#/usr/bin/ld.bfd.real: cannot find /usr/bin/../lib/clang/3.4/lib/linux/libclang_rt.asan-arm.a: No such file or directory
#too lazy to debug, didn't build with ASAN on ARM
export CFLAGS="-Wall -g -fstack-protector-all -fsanitize=address -fno-omit-frame-pointer" && export CC=$COMPILER_C && export CXX=$COMPILER_CPP && ./configure --prefix="`pwd`/installed/" && make clean && make && make install
cp ./installed/etc/freshclam.conf.sample ./installed/etc/freshclam.conf
sed -i 's/Example//g' ./installed/etc/freshclam.conf
cp ./installed/etc/clamd.conf.sample ./installed/etc/clamd.conf
sed -i 's/Example//g' ./installed/etc/clamd.conf
./installed/bin/freshclam
cd ..
