.PHONY: book clean test

book:
	lake build jarbook
	.lake/build/bin/jarbook

test:
	lake build Jar Genesis genesis

clean:
	rm -rf _out
