#!/bin/sh
rm dotsd_localhost*
dotsd -Y example_policy.html -V -V -P a/a/a/a/ -H localhost0 localhost0 localhost1 localhost2 localhost3 >dotsd_localhost0.stdout 2>dotsd_localhost0.stderr &
dotsd -V -V -P a/a/a/a/ -H localhost1 localhost0 localhost1 localhost2 localhost3 >dotsd_localhost1.stdout 2>dotsd_localhost1.stderr &
dotsd -V -V -P a/a/a/a/ -H localhost2 localhost0 localhost1 localhost2 localhost3 >dotsd_localhost2.stdout 2>dotsd_localhost2.stderr &
dotsd -V -V -P a/a/a/a/ -H localhost3 localhost0 localhost1 localhost2 localhost3 >dotsd_localhost3.stdout 2>dotsd_localhost3.stderr &
tail -f dotsd_localhost0.stderr
killall dotsd
echo "test finished"

