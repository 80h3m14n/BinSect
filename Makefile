CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
LIBS = -lm -ldl
TARGET = binsect
SRC_DIR = src
INCLUDE_DIR = include
SOURCES = $(SRC_DIR)/cli.c $(SRC_DIR)/analysis.c $(SRC_DIR)/disassemble.c $(SRC_DIR)/output.c $(SRC_DIR)/formats.c $(SRC_DIR)/packer.c $(SRC_DIR)/advanced_formats.c $(SRC_DIR)/module_registry.c $(SRC_DIR)/plugin.c
OBJECTS = $(SOURCES:.c=.o)
PLUGIN_DIR = plugins
PLUGIN_SAMPLE_SRC = $(PLUGIN_DIR)/sample_plugin.c
PLUGIN_SAMPLE_SO = $(PLUGIN_DIR)/sample_plugin.so

all: $(TARGET) cleanup

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

%.o: %.c $(INCLUDE_DIR)/core_types.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(PLUGIN_SAMPLE_SO): $(PLUGIN_SAMPLE_SRC) $(INCLUDE_DIR)/plugin.h $(INCLUDE_DIR)/module_registry.h $(INCLUDE_DIR)/core_types.h
	$(CC) $(CFLAGS) -fPIC -shared -I$(INCLUDE_DIR) -o $(PLUGIN_SAMPLE_SO) $(PLUGIN_SAMPLE_SRC) -lm

plugins: $(PLUGIN_SAMPLE_SO)

# Automatically clean up object files after successful build
cleanup:
	@echo "Cleaning up build artifacts..."
	@rm -f $(OBJECTS)
	@echo "Build complete. Only keeping source files and executable."

clean:
	rm -f $(TARGET) $(OBJECTS) $(TARGET)_debug $(PLUGIN_SAMPLE_SO)

# Clean everything including executables
distclean: clean
	@echo "Removed all generated files. Only source code remains."

run: $(TARGET)
	./$(TARGET)

debug: $(SOURCES)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -DDEBUG -g -o $(TARGET)_debug $(SOURCES) $(LIBS)
	gdb ./$(TARGET)_debug

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Build and immediately clean, keeping only executable and source
release: all
	@echo "Release build complete!"
	@echo "Executable: $(TARGET)"
	@echo "Source files preserved: *.c, *.h, Makefile, README.md"

.PHONY: all clean distclean run debug install cleanup release plugins
