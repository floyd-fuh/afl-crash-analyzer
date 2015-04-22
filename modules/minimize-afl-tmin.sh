
#see https://code.google.com/p/tmin/
DIR="crashes"
TMP_FILE="/tmp/testfile$RANDOM"
BIN="/opt/tiff-4.0.3-gcc/tools/tiffdump"
BIN_ARGS="$TMP_FILE"
TMIN="/opt/tools/tmin/tmin"
TMIN_ARGS="-w $TMP_FILE"

find ./$DIR -type f -print0 | while read -d $'\0' f
do
   FILENAME=`basename $f`
   echo "Working on $FILENAME"
   mv $f ./testcase.in
   #sleep 1
   $TMIN $TMIN_ARGS $BIN $BIN_ARGS
   mv ./testcase.small $f
   #sleep 3
done