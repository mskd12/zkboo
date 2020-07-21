default: prover verifier
prover: prover.c zklib.h shared.h aes.h
	gcc -std=c99 -g -Wall -fopenmp -o prover prover.c -L/usr/local/lib -lssl -lcrypto

verifier: verifier.c zklib.h shared.h aes.h
	gcc -std=c99 -g -fopenmp -o verifier verifier.c -L/usr/local/lib -lssl -lcrypto


clean:
	-rm -f *.o
	-rm -f prover verifier
