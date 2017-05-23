PubLib = -lpcap
LibPath = ./
IncPath = ./

ExecFile = exec

all:$(ExecFile)

$(ExecFile):stream_test.c
	gcc $^ -o $@ $(PubLib)

clean:
	rm -rf *.o $(ExecFile)
.PHONY: clean
