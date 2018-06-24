X=$(shell objdump -d ./hello | grep print_hello | grep -o "\b[0-9]\{16\}\b")

default:
	gcc hello.c -o hello
	gcc strace.c -o strace
	gcc singlestep.c -o step
	gcc breakpoint.c -o breakpoint
	gcc -c hello.s && ld hello.o -o hello-asm

test:
	./strace ./hello
	./step ./hello-asm
	./breakpoint ./hello $(X)

clean:
	rm ./hello
	rm ./hello-asm
	rm ./hello.o
	rm ./strace
	rm ./step
	rm ./breakpoint