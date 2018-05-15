#!/bin/sh
for i in $(seq 1 50)
do
	value=`expr $i \* 2000`
	time ./test_build_speed rules_$value
done