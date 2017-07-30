#!/bin/sh
for i in /,0 None,0 setup.php,1 aa/bb/xsetup.php12345,1 wallet,2 walle,0 allet,0 xpwalletabc,2 ; do 
  URI=${i%,*};
  RC=${i#*,};
  ./banmoron.cgi $URI
  R=$?
  if [ $R -ne $RC ]; then
    echo "ERROR: $URI Program returned $R when expected $RC"
    exit
  else
    echo "Test OK"
  fi
done

