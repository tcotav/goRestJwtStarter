#!/bin/bash

#echo
#echo "an  invalid user"
#curl -H "Content-Type: application/json" -X POST \
#  -d '{"user":"user9","pass":"p9"}' \
#  http://localhost:8000/login/user9
#
echo
echo " a valid user"
echo
curl -c cookies.txt -H "Content-Type: application/json" -X POST -d '{"user":"user1","pass":"p1"}' http://localhost:8000/login/user1  
echo

curl -b cookies.txt -H "Content-Type: application/json"  -X POST -d "{\"session\":\"${TOKEN}\"}"  http://localhost:8000/testsession
echo
echo
curl -H "Content-Type: application/json"  -X POST -d "{\"session\":\"${TOKEN}\"}"  http://localhost:8000/testsession
echo
echo
