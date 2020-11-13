objs=testmain.o sm3.o sha256.o
all:${objs}
	g++ $^ -o testmain.elf



%.o:%.cpp
	g++ -c $< -o $@ -Wall -O2

%.o:%.c
	gcc -c $< -o $@ -Wall -O2

clean:
	rm -f ./*.o ./*.elf