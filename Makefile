.PHONY: all device host clean

all: device host

# Build mxhelper into mxrestore/payload/PersistenceHelper_Embedded.
# Must run on macOS with Theos + Xcode CLT (Linux won't work; TrollStore's
# Theos Makefile pulls in iphoneos-clang, libarchive headers, etc.).
device:
	@$(MAKE) -C mxhelper

# Host-side Python: just install deps in-place so mxrestore.py is runnable.
# Cross-platform (Mac/Linux/Windows with iTunes).
host:
	@pip3 install -r mxrestore/requirements.txt

clean:
	@$(MAKE) -C mxhelper clean
