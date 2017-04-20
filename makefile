all:
	gcc rule_stats.c -o rule_stats
	gcc rule_convertor.c -o rule_convertor
	gcc rule_filter.c -o rule_filter
	gcc rule_eliminator.c -o rule_eliminator
	gcc rule_normalizer.c double_list.c -o rule_normalizer
	gcc test_read_rules.c build_server.c double_list.c rule.c signature_fragment.c -o test_read_rules
clean:
	rm -f rule_stats
	rm -f rule_convertor
	rm -f rule_filter
	rm -f rule_eliminator
	rm -f rule_normalizer
	rm -f test_read_rules