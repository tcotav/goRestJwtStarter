## Golang JWT-SecureCookie HTTP Web REST Project Starter

Simple golang starter project (clone and use as the base for a REST web service) that uses JWT and secure cookies for session authentication.

### Libraries

```
  "github.com/dgrijalva/jwt-go"
  "github.com/gorilla/handlers"
  "github.com/gorilla/mux"
  "github.com/gorilla/securecookie"
``` 

I use `gb` for vendoring so its `gb vendor fetch ` each of the above. 


### TODO 

  - add https 

### HTTPS 

ref: https://github.com/denji/golang-tls

```
openssl genrsa -out server.key 2048

openssl ecparam -genkey -name secp384r1 -out server.key

openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```


