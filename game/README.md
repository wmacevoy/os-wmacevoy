# Game of Chance

Game starts with two players each with 1 dollar.

In each turn,
* A fair coin is tossed
* The winner gets 1/2 of the losers money.

The simulation gives the probabilities and outcomes after 10 turns.

## Build

```bash
gcc -o game game.c
```

## Run
To produce the CSV file of outcomes:
```bash
nice ./game > game.csv
```
