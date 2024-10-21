packet_sniffer: packet_sniffer.c
	gcc -c packet_sniffer.c -ggdb
	gcc packet_sniffer.o -o packet_sniffer 
