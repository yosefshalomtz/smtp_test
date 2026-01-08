EXECUTABLE = smtp
SOURCES = main.c smtp.c
HEADERS = smtp.h
LIBRARIES = -lcrypto -lssl -lreadline

$(EXECUTABLE): $(SOURCES) $(HEADERS)
	gcc -o $(EXECUTABLE) $(SOURCES) $(LIBRARIES)