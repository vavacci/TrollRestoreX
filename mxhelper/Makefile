.PHONY: all clean

all:
	@./build.sh

clean:
	@cd ../third_party/TrollStore/TrollHelper && $(MAKE) clean || true
	@rm -f ../mxrestore/payload/PersistenceHelper_Embedded
