#!/bin/bash

#echo
#echo "an  invalid user"
#curl --insecure -H "Content-Type: application/json" -X POST \
#  -d '{"user":"user9","pass":"p9"}' \
#  http://localhost:8000/login/user9
#
echo
echo " a valid user"
echo
curl --insecure -c cookies.txt -H "Content-Type: application/json" -X POST -d '{"user":"user1","pass":"p1"}' https://localhost:8000/login/user1  
echo

curl --insecure -b cookies.txt -H "Content-Type: application/json"  -X POST -d "{\"session\":\"${TOKEN}\"}"  https://localhost:8000/testsession
echo
echo
curl --insecure -H "Content-Type: application/json"  -X POST -d "{\"session\":\"${TOKEN}\"}"  https://localhost:8000/testsession
echo
echo
