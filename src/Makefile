CC	?=	cc
LD	= 	$(CC)

CFLAGS	+=	-Wall -Os
OBJ	=	banmoron.o

PROJECT	= 	banmoron.cgi

# Default install root
CGIPATH	?=	/usr/local/www/apache24/cgi-bin/

all: $(PROJECT)

.c:.o $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROJECT): $(OBJ)
	$(LD) -o $@ $(OBJ)

clean:
	rm -f $(OBJ) $(PROJECT)

install:
	install -s -m 755 $(PROJECT) $(CGIPATH)
	chmod u+s	$(CGIPATH)$(PROJECT)	
