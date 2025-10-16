.PHONY: clean all

all: clean build

build: pam_authenticated_printf.c
	gcc -DDEBUG pam_authenticated_printf.c -o pam_authenticated_printf -lpam -lpam_misc

clean:
	rm -rf pam_authenticated_printf
