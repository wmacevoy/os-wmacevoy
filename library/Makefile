# Compiler and flags
CC = gcc
CFLAGS = -fPIC -Iinclude

# Version numbers
MAJOR = 1
MINOR = 0
REVISION = 0
VERSION = $(MAJOR).$(MINOR).$(REVISION)

# Library names
LIBNAME = libshoesize.so
SONAME = $(LIBNAME).$(MAJOR)
REALNAME = $(LIBNAME).$(VERSION)

# Directories
INCDIR = include
SRCDIR = src
OBJDIR = obj

# Source and object files
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

.PHONY: all clean

# Default target
all: $(REALNAME) symlinks

# Build the shared library with versioning
$(REALNAME): $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $(REALNAME) $(OBJS)

# Create symbolic links
symlinks:
	ln -sf $(REALNAME) $(SONAME)
	ln -sf $(SONAME) $(LIBNAME)

# Clean up generated files
clean:
	rm -f $(OBJS) $(REALNAME) $(SONAME) $(LIBNAME)
	rm -rf $(OBJDIR)

# Compile source files into object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create the object directory if it doesn't exist
$(OBJDIR):
	mkdir -p $(OBJDIR)
