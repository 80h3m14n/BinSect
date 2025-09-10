CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
TARGET = sentinelsec
SOURCES = cli.c analysis.c disassemble.c output.c formats.c packer.c advanced_formats.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET) cleanup

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) -lm

%.o: %.c disassembler.h
	$(CC) $(CFLAGS) -c $< -o $@

# Automatically clean up object files after successful build
cleanup:
	@echo "Cleaning up build artifacts..."
	@rm -f $(OBJECTS)
	@echo "Build complete. Only keeping source files and executable."

clean:
	rm -f $(TARGET) $(OBJECTS) $(TARGET)_debug

# Clean everything including executables
distclean: clean
	@echo "Removed all generated files. Only source code remains."

run: $(TARGET)
	./$(TARGET)

debug: $(SOURCES)
	$(CC) $(CFLAGS) -DDEBUG -g -o $(TARGET)_debug $(SOURCES)
	gdb ./$(TARGET)_debug

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Build and immediately clean, keeping only executable and source
release: all
	@echo "Release build complete!"
	@echo "Executable: $(TARGET)"
	@echo "Source files preserved: *.c, *.h, Makefile, README.md"

.PHONY: all clean distclean run debug install cleanup release
