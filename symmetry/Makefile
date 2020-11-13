objs=testmain.o sm4.o
all:${objs}
	g++ $^ -o testmain.elf



%.o:%.cpp
	g++ -c $< -o $@ -Wall -O2

clean:
	rm -f ./*.o