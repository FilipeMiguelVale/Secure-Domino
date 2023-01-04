# Security Domino Project 2020
This is a project made for Security class @DETI

## Server

## Client
There are some inputs that you can uncomment for debugging purpose
## Usage
Start the server to wait for clients
>python3 server.py [numclients]

Start clients running this command for each client
>python3 client.py [-nick Name] [-cheat]

The flag -nick will determine the use of a nickname chosen by the user

The flag -cheat will determine the degree of customer autonomy and the ability to do cheating
 
## Scripts
To use the scripts you need to  souce the script into your shell
>source script.sh

Then you can use the scripts listed:
To start a client:
> c

To start the server:
> s

To start one server and multiple clients:
>run_all 

or 
>run_all -num_clients=x -max_clients=y

the default value of x and y is 4.
    