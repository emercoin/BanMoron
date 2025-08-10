#!/bin/sh
for i in /,0 None,0 setup.php,3 aa/bb/xsetup.php12345,3 wallet,2 walle,0 allet,0 \
	xpwalletabc,2 1/2Detect.js.php2,3 2Detect.js.ph1,0 /hndUnblock.cgi,2 \
	http://proxyscan,1 /w00tw00t,3 z/../../a.cgi,3 test-cgi,3
do 
  URI=${i%,*};
  RC=${i#*,};
  ./banmoron.cgi $URI
  R=$?
  if [ $R -ne $RC ]; then
    echo "!!!ERROR: $URI Program returned $R when expected $RC"
    exit
  else
    echo "Test [$URI] [OK]"
  fi
  echo
done

