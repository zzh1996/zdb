all:zdb test

clean:
	rm -f zdb test

test:test.c
	gcc test.c -o test -Wall -g

zdb:zdb.c
	gcc zdb.c -o zdb -Wall -lbfd -g

