PubLib = -lpcap
LibPath = ./
IncPath = ./

ExecFile = TCP_STREAM_pcap

all:$(ExecFile)

$(ExecFile):TCP.STREAM_pcap.c
	gcc $^ -o $@ $(PubLib)

clean:
	rm -rf *.o $(ExecFile)
.PHONY: clean
