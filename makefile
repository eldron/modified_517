all:
	gcc rule_stats.c -o rule_stats
	gcc rule_convertor.c -o rule_convertor
	gcc rule_filter.c -o rule_filter
	gcc rule_eliminator.c -o rule_eliminator
clean:
	rm -f rule_stats
	rm -f rule_convertor
	rm -f rule_filter
	rm -f rule_eliminator