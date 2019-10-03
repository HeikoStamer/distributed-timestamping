#!/bin/sh
rm dotsd_localhost*
echo "test started"
dotsd -Y example_policy.html -V -V -P a/b/c/d/ -H localhost0 localhost0 localhost1 localhost2 localhost3 >dotsd_localhost0.stdout 2>dotsd_localhost0.stderr &
dotsd -Y example_policy.html -V -V -P b/e/f/g/ -H localhost1 localhost0 localhost1 localhost2 localhost3 >dotsd_localhost1.stdout 2>dotsd_localhost1.stderr &
dotsd -Y example_policy.html -V -V -P c/f/h/i/ -H localhost2 localhost0 localhost1 localhost2 localhost3 >dotsd_localhost2.stdout 2>dotsd_localhost2.stderr &
dotsd -Y example_policy.html -V -V -P d/g/i/j/ -H localhost3 localhost0 localhost1 localhost2 localhost3 >dotsd_localhost3.stdout 2>dotsd_localhost3.stderr &
sleep 1
tail -f dotsd_localhost0.stderr
killall dotsd
echo "test finished"

