all:
	gcc rule_stats.c -o rule_stats
	gcc rule_convertor.c -o rule_convertor
	gcc rule_filter.c -o rule_filter
	gcc rule_eliminator.c -o rule_eliminator
	gcc rule_normalizer.c double_list.c -o rule_normalizer
	gcc test_read_rules.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c -o test_read_rules
	gcc test_insert_signatures.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c -o test_insert_signatures

clean:
	rm -f rule_stats
	rm -f rule_convertor
	rm -f rule_filter
	rm -f rule_eliminator
	rm -f rule_normalizer
	rm -f test_read_rules
	rm -f test_insert_signatures