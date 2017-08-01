CC	?=	cc
LD	= 	$(CC)

CFLAGS	=	-Wall -Os -pipe
#CFLAGS	=	-Wall -g -pipe
OBJ	=	banmoron.o

PROJECT	= 	banmoron.cgi
OWNER	=	root
GROUP	=	www

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
	install -s -m 4750 -o $(OWNER) -g $(GROUP) $(PROJECT) $(CGIPATH)
