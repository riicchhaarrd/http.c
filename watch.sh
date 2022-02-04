#!/bin/bash

echo "Watching $1"
inotifywait -m -e close_write $1 |
while read filename eventlist eventfile
do
	if [ "$eventfile" = "http.c" ]; then
		#echo $eventlist
		#echo $eventfile
		echo "Compiling..."
		gcc -g -I../rhd http.c
		pkill a.out
		#kill $(pgrep -f valgrind)
		echo "Running..."
		./a.out&
		#valgrind ./a.out&
	fi
done
