#!/bin/bash

gcc -o process process.c || exit 1

./process 2 &
./process 2 &
./process 2 &
./process 2 &

ps
