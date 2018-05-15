#!/bin/sh
for i in $(seq 1 50)
do
	value=`expr $i \* 2000`
	echo $value
	./rule_grouper new_normalized_rules.txt $value > rules_$value
done
