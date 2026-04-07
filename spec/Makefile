.PHONY: book clean test

book:
	lake build jarbook
	.lake/build/bin/jarbook

test:
	lake build jartest
	.lake/build/bin/jartest

clean:
	rm -rf _out
