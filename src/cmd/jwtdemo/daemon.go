package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type LoginUser struct {
	User      string `json:"user"`
	Pass      string `json:"pass"`
	SessionId string `json:"session"`
}

type Session struct {
	Session string    `json:"session"`
	User    string    `json:"user"`
	Expires time.Time `json:"expires"`
}

type MsgResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

const SESSION_DURATION time.Duration = 15 * 60 * time.Second
const INVALIDLOGIN_RESPONSE string = "Invalid login"
const INVALIDSESS_RESPONSE string = "Invalid session"
const NOCOOKIE_RESPONSE string = "No cookie found.  please log in."

var sessionMap map[string]time.Time
var passwordMap map[string]string
var hmacSecret []byte
var sCookie *securecookie.SecureCookie

func ReturnError(w http.ResponseWriter, s string) {
	w.WriteHeader(http.StatusUnauthorized)
	sobj := MsgResponse{http.StatusUnauthorized, s}
	resp, _ := json.Marshal(sobj)
	w.Write(resp)
}

// /login/{user} -- in the url for logging purposes
func UserLoginHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// login urlPathUser
	urlPathUser := vars["user"]

	var lu LoginUser
	b, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(b, &lu)

	// do some checks
	if lu.User != urlPathUser {
		log.Print(fmt.Sprintf("url user, %s, does not match payload json user, %s", lu.User, urlPathUser))
		ReturnError(w, INVALIDLOGIN_RESPONSE)
		return
	}

	// check if user exists in internal hash
	if ppasswd, ok := passwordMap[urlPathUser]; ok {
		// confirm password
		if lu.Pass != ppasswd {
			log.Print("invalid password")
			ReturnError(w, INVALIDLOGIN_RESPONSE)
			return
		}
	} else {
		log.Print(fmt.Sprintf("User %s not found in internal user list ", urlPathUser))
		ReturnError(w, INVALIDLOGIN_RESPONSE)
		return
	}
	// then return a session
	token, err := CreateSessionToken(lu.User)
	if err != nil {
		log.Printf("Create token session error: %s\n", err)
		ReturnError(w, INVALIDLOGIN_RESPONSE)
	}
	s := Session{Session: token}
	if encoded, err := sCookie.Encode("session", s); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	} else {
		log.Println("Error setting cookie", err)
	}

	w.WriteHeader(http.StatusOK)
}

func hmacInit(keyName string) {
	if keyData, e := ioutil.ReadFile(keyName); e == nil {
		hmacSecret = keyData
	} else {
		panic(e)
	}
}

func getToken(luser string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	// see http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.5
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"luser": luser,
		"nbf":   time.Now().Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSecret)
	return tokenString, err
}

func LoadUserConf(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bufio.NewReader(f))
	//user:pass
	for scanner.Scan() {
		words := strings.Split(scanner.Text(), ":")
		if len(words) != 2 {
			return errors.New(fmt.Sprintf("Invalid password line: %s", words))
		}
		passwordMap[words[0]] = words[1]
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func CreateSessionToken(username string) (string, error) {
	if sessionMap == nil {
		sessionMap = make(map[string]time.Time)
	}

	token, err := getToken(username)
	if err != nil {
		log.Print(err)
	}
	log.Printf("token created: %s\n", token)
	sessionMap[token] = time.Now()
	return token, err
}

func verifyJWT(tokenString string) bool {
	if v, ok := sessionMap[tokenString]; ok {
		// test if v
		now := time.Now()
		if now.Sub(v) > SESSION_DURATION {
			log.Print("Session expired.")
			return false
		} else {
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
				return hmacSecret, nil
			})

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				log.Printf("%s, %s", claims["foo"], claims["nbf"])
				return true
			} else {
				log.Printf("Error in validating token: %s", err)
				return false
			}
		}
	} else {
		log.Printf("Session not in map: %s.\n", tokenString)
	}
	return false
}

func IsValidSession(w http.ResponseWriter, r *http.Request) bool {
	var s Session
	if cookie, err := r.Cookie("session"); err == nil {
		if err = sCookie.Decode("session", cookie.Value, &s); err != nil {
			return false
		}
	} else {
		log.Println("No cookie found in request")
		return false
	}

	if verifyJWT(s.Session) {
		return true
	} else {
		return false
	}
}

func TestSessionHandler(w http.ResponseWriter, r *http.Request) {
	if !IsValidSession(w, r) {
		ReturnError(w, INVALIDSESS_RESPONSE)
		return
	}
	w.WriteHeader(http.StatusOK)
	sobj := MsgResponse{http.StatusOK, "testsession ok"}
	resp, _ := json.Marshal(sobj)
	w.Write(resp)

}

func main() {

	// just need some bytes for hmacInit -- maybe use a better source
	hmacInit("passwd.cfg")
	passwordMap = make(map[string]string)
	sessionMap = make(map[string]time.Time)

	// load up the user config for logins
	err := LoadUserConf("passwd.cfg")
	if err != nil {
		log.Fatal(err)
	}

	var hashKey = securecookie.GenerateRandomKey(16)
	var blockKey = securecookie.GenerateRandomKey(16)
	sCookie = securecookie.New(hashKey, blockKey)

	r := mux.NewRouter()
	// this one function will be outside the auth check
	r.HandleFunc("/login/{user}", UserLoginHandler).Methods("POST")

	r.HandleFunc("/testsession", TestSessionHandler).Methods("POST")

	loggedRouter := handlers.LoggingHandler(os.Stdout, r)
	listenPort := ":8000"
	log.Printf("Listening at %s\n", listenPort)
	// Bind to a port and pass our router in
	log.Fatal(http.ListenAndServe(listenPort, loggedRouter))
}
