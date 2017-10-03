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
TOKEN=`curl -H "Content-Type: application/json" -X POST -d '{"user":"user1","pass":"p1"}' http://localhost:8000/login/user1  | jq ".session" | tr -d '"'`
echo

curl -H "Content-Type: application/json"  -X POST -d "{\"session\":\"${TOKEN}\"}"  http://localhost:8000/authcheck 
echo
echo
