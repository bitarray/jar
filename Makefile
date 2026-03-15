BOOK_BIN := .lake/build/bin/jarbook
OUT_DIR  := _out/html-multi
BRANCH   := gh-pages
REMOTE   := origin

TEST_BINS := cryptotest safrolejsontest historyjsontest statisticsjsontest \
             authorizationsjsontest disputesjsontest preimagesjsontest \
             assurancesjsontest reportsjsontest accumulatejsontest propertytest \
             trietest shuffletest codectest blocktest erasuretest

.PHONY: book deploy clean test

book: $(BOOK_BIN)
	$(BOOK_BIN)

$(BOOK_BIN):
	lake build jarbook

deploy: book
	@if ! git diff --quiet; then echo "Error: working tree is dirty"; exit 1; fi
	@COMMIT=$$(git rev-parse --short HEAD) && \
	TMPDIR=$$(mktemp -d) && \
	cp -r $(OUT_DIR)/. $$TMPDIR && \
	git checkout $(BRANCH) 2>/dev/null || git checkout --orphan $(BRANCH) && \
	git rm -rf --quiet . 2>/dev/null || true && \
	cp -r $$TMPDIR/. . && \
	rm -rf $$TMPDIR && \
	git show master:.gitignore > .gitignore && \
	git add -A && \
	git commit -m "Deploy JAR book from $$COMMIT" && \
	git push $(REMOTE) $(BRANCH) && \
	git checkout -

test:
	lake build $(TEST_BINS)
	@fail=0; \
	for bin in $(TEST_BINS); do \
	  echo "── $$bin ──"; \
	  .lake/build/bin/$$bin || fail=1; \
	done; \
	exit $$fail

clean:
	rm -rf _out
