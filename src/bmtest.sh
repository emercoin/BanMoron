#!/bin/sh
for i in /,0 None,0 setup.php,1 aa/bb/xsetup.php12345,1 wallet,1 walle,0 allet,0 \
	xpwalletabc,1 1/2Detect.js.php2,1 2Detect.js.ph1,0 /hndUnblock.cgi,1 \
	http://proxyscan,1 /w00tw00t,1
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

