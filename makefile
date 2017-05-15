all:
	gcc rule_stats.c -o rule_stats
	gcc rule_convertor.c -o rule_convertor
	gcc rule_filter.c -o rule_filter
	gcc rule_eliminator.c -o rule_eliminator
	gcc rule_normalizer.c double_list.c -o rule_normalizer
	gcc test_read_rules.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c sfet.c -o test_read_rules
	gcc test_insert_signatures.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c inspection.c sfet.c -o test_insert_signatures
	gcc cloud_dpi_server.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c inspection.c sfet.c -o cloud_dpi_server
	gcc cloud_dpi_client.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c sfet.c -o cloud_dpi_client
	gcc test_check_local_files.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c inspection.c sfet.c -o test_check_local_files
	gcc check_one_file.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c sfet.c -o check_one_file
	gcc test_search_speed_server.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c inspection.c sfet.c -o test_search_speed_server
	gcc test_search_speed_client.c build_server.c double_list.c rule.c signature_fragment.c aes.c reversible_sketch.c murmur3.c list.c memory_pool.c sfet.c -o test_search_speed_client

clean:
	rm -f rule_stats
	rm -f rule_convertor
	rm -f rule_filter
	rm -f rule_eliminator
	rm -f rule_normalizer
	rm -f test_read_rules
	rm -f test_insert_signatures
	rm -f cloud_dpi_server
	rm -f cloud_dpi_client
	rm -f check_one_file
	rm -f test_search_speed_server
	rm -f test_search_speed_client
