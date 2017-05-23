PubLib = -lpcap
LibPath = ./
IncPath = ./include

ExecFile = exec

all:$(ExecFile)

$(ExecFile):stream_log.c
	gcc $^ -o $@ $(PubLib) -I $(IncPath)

clean:
	rm -rf *.o $(ExecFile) && > log.txt
.PHONY: clean
