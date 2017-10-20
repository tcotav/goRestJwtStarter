## Golang JWT-SecureCookie HTTP Web REST Project Starter

Simple golang starter project (clone and use as the base for a REST web service) that uses JWT and secure cookies for session authentication.

Supports HTTPS but keys will have to be provided or generated.

### Config is in json

```
{
  "listenPort":":8000",
  "runSecure":"true",
  "serverKey":"keys/server.key",
  "serverCert":"keys/server.crt",
  "userconf":"passwd.cfg",
  "cookieKeyFile":"keys/cookiehash",
  "hmacSecret":"keys/secret"
}
```

- listen port -- port server will listen on
- runSecure -- run as HTTPS server
- serverKey -- key for https support otherwise not needed, requires runSecure=true
- serverCert -- key for https support otherwise not needed, requires runSecure=true
- userconf -- list of user, password that can sign into server # pretty crude at this point
- cookieKeyFile -- secret to use for generating our cookies (server generates in specified location)
- hmacSecret -- secret to use for JWT (server generates in specified location)

### Create your users 

One per line, user and password separated by a comma.

```
user1,pass1

```

defaults to `passwd.cfg`


### HTTPS 

Generate keys in your keys/ directory for the HTTPS server if needed.

```
openssl genrsa -out server.key 2048

openssl ecparam -genkey -name secp384r1 -out server.key

openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```


### Logging 

Defaults to stdout.  I should fix that maybe.  Or just pipe it to some outfile.

### Libraries

```
  "github.com/dgrijalva/jwt-go"
  "github.com/gorilla/handlers"
  "github.com/gorilla/mux"
  "github.com/gorilla/securecookie"
  "github.com/spf13/viper"
``` 


