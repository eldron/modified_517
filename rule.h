#ifndef __rule__h
#define __rule__h

struct rule{
	char * rule_name;
	void * first_signature_fragment;// points to the first signature fragment, cast this to (struct signature_fragment *)
};

void initialize_rule(struct rule * r){
	r->rule_name = NULL;
	r->first_signature_fragment = NULL;
}

#endif