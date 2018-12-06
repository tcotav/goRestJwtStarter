package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/patrickmn/go-cache"
	"github.com/spf13/viper"
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
	Token   string    `json:"token"`
	User    string    `json:"user"`
	Expires time.Time `json:"expires"`
}

type MsgResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

const USER_KEY_PREFIX string = "US"
const TOKEN_KEY_PREFIX string = "TK"

const SESSION_DURATION time.Duration = 15 * 60 * time.Second
const INVALIDLOGIN_RESPONSE string = "Invalid login"
const INVALIDSESS_RESPONSE string = "Invalid session"
const NOCOOKIE_RESPONSE string = "No cookie found.  please log in."

var passwordMap map[string]string
var hmacSecret []byte
var sCookie *securecookie.SecureCookie
var redisDb *redis.Client

var redisAddress, redisPassword, redisDatabase string
var useRedis bool
var sessionDuration time.Duration
var localCache *cache.Cache

func ReturnError(w http.ResponseWriter, s string) {
	w.WriteHeader(http.StatusUnauthorized)
	sobj := MsgResponse{http.StatusUnauthorized, s}
	resp, _ := json.Marshal(sobj)
	w.Write(resp)
}

/*
* Put whatever authorization mechanism is appropriate here -- i.e. ldap lookup.
* We just use a simple config file -> map lookup
 */
func checkUserPassword(lu LoginUser) bool {

	if ppasswd, ok := passwordMap[lu.User]; ok {
		// confirm password
		if lu.Pass != ppasswd {
			log.Print("invalid password")
			return false
		}
		return true
	} else {
		log.Print(fmt.Sprintf("User %s not found in internal user list ", lu.User))
		return false
	}
}

// /login -- in the url for logging purposes
func UserLoginHandler(w http.ResponseWriter, r *http.Request) {

	var lu LoginUser
	b, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(b, &lu)

	if !checkUserPassword(lu) {
		ReturnError(w, INVALIDLOGIN_RESPONSE)
	}

	// so after this point -- they should be golden -- authN completed
	// then return a session
	token, err := GetSessionToken(lu.User)
	if err != nil {
		log.Printf("Create token session error: %s\n", err)
		ReturnError(w, INVALIDLOGIN_RESPONSE)
	}
	if encoded, err := sCookie.Encode("session", token); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	} else {
		log.Println("Error setting cookie", err)
	}

	log.Print("Successful login for user: ", lu.User)
	w.WriteHeader(http.StatusOK)
}

func hmacInit(secretFile string) []byte {
	if sData, e := ioutil.ReadFile(secretFile); e == nil {
		return []byte(sData)
	} else {
		sData := securecookie.GenerateRandomKey(16)
		err := ioutil.WriteFile(secretFile, sData, 0600)
		if err != nil {
			log.Fatal("Could not write secret file at: ", secretFile)
		}
		return sData
	}
}

func createUserToken(luser string) (string, error) {
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

/*
* reset the key TTL in all caches
 */
func resetKeyTTL(k string, v string) error {
	localCache.Set(k, v, sessionDuration)
	if !useRedis {
		keyExists, err := redisDb.SetNX(k, v, sessionDuration).Result()
		if keyExists { // bump the ttl of the key
			setExpire, err2 := redisDb.Expire(k, sessionDuration).Result()
			if !setExpire {
				log.Print(fmt.Sprintf("Could not update expiration for key: %s", k))
			}
			err = err2
		}
		return err
	}
	return nil
}

/*
Encapsulating saving the sesssion
*/
func SaveSession(s Session) error {

	err := resetKeyTTL(s.User, s.Token)
	if err != nil {
		return err
	}
	err = resetKeyTTL(s.Token, s.User)
	return err
}

func GetKeyFromCache(k string) (string, error) {
	var err error
	var v string
	// try local cache
	vIf, isPresent := localCache.Get(k)
	if !isPresent {
		if !useRedis {
			//then go to redis
			v, err = redisDb.Get(k).Result()
			if err != nil {
				log.Println("Redis miss", k)
				return "", err
			}
			return "", err
		} else {
			return "", errors.New("key not found")
		}
	} else {
		v = fmt.Sprintf("%v", vIf)
	}
	return v, nil
}

func GetSessionByToken(t string) (string, error) {
	return GetKeyFromCache(t)
}

func GetSessionByUser(username string) (string, error) {
	return GetKeyFromCache(username)
}

func GetSessionToken(username string) (string, error) {

	// does user + token already exist?
	s, err := GetSessionByUser(username)
	if err != nil {
		return s, nil
	}

	// else we build one
	token, err := createUserToken(username)
	if err != nil {
		log.Print(err)
	}
	sess := Session{Token: token, User: username}
	err = SaveSession(sess)
	if err != nil {
		log.Print(err)
	}
	return token, err
}

func verifyJWT(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSecret, nil
	})

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true
	} else {
		log.Printf("Error in validating token: %s", err)
		return false
	}
	return false
}

func IsValidSession(w http.ResponseWriter, r *http.Request) bool {
	var s string
	if cookie, err := r.Cookie("session"); err == nil {
		if err = sCookie.Decode("session", cookie.Value, &s); err != nil {
			return false
		}
	} else {
		log.Println("No cookie found in request")
		return false
	}

	// confirm it is in the map
	username, err := GetSessionByToken(s)
	if username != "" {
		log.Println("session check for user: ", username)
	} else if err != nil {
		log.Println(err)
		return false
	} else {
		log.Println("Session token not found or expired")
		return false
	}

	if verifyJWT(s) {
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

func GetOrGenHash(fileName string, secret []byte) string {
	var retString string

	// check if file exists at `filename`
	if keyData, e := ioutil.ReadFile(fileName); e == nil {
		// if it does, read it in and go on
		retString = string(keyData)
	} else {
		log.Println("creating file: ", fileName)
		// if it does not, generate it, save it to `filename`
		h := hmac.New(sha256.New, secret)
		h.Write(secret)
		retString = base64.StdEncoding.EncodeToString(h.Sum(nil))
		err := ioutil.WriteFile(fileName, []byte(retString), 0600)
		if err != nil {
			log.Fatal("Could not write hash file at: ", fileName)
		}
	}
	// and go on
	return retString
}

func GetCookieKeys(cookieKeyFile string) []string {
	if keyData, e := ioutil.ReadFile(cookieKeyFile); e == nil {
		keyLines := strings.Split(string(keyData), "\n")
		if len(keyLines) != 2 {
			log.Fatal("Invalid cookie key file: ", cookieKeyFile)
		}
		return keyLines
	} else {
		keyLines := make([]string, 2)
		for i := 0; i < 2; i++ {
			keyLines[i] = string(securecookie.GenerateRandomKey(16))
		}
		err := ioutil.WriteFile(cookieKeyFile, []byte(strings.Join(keyLines, "\n")), 0600)
		if err != nil {
			log.Fatal("Could not write cookie key file at: ", cookieKeyFile)
		}
		return keyLines
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	viper.SetConfigName("config") // name of config file (without extension)
	viper.AddConfigPath("/etc/webjwt/")
	viper.AddConfigPath("$HOME/.webjwt")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	viper.SetDefault("listenPort", ":8000")
	viper.SetDefault("serverKey", "key.pem")
	viper.SetDefault("serverCert", "crt.pem")
	viper.SetDefault("userconf", "passwd.cfg")
	viper.SetDefault("runSecure", true)
	viper.SetDefault("cookieKeyFile", "cookieKeys.txt")
	viper.SetDefault("hmacSecret", "secret.txt")
	viper.SetDefault("redis.use", false)
	viper.SetDefault("sessionDuration", SESSION_DURATION)

	listenPort := viper.GetString("listenPort")
	userConf := viper.GetString("userconf")
	cookieKeyFile := viper.GetString("cookieKeyFile")
	serverKey := viper.GetString("serverKey")
	serverCert := viper.GetString("serverCert")

	// redis config
	useRedis := viper.GetBool("redis.use")
	if useRedis {
		redisAddress := viper.GetString("redis.address")
		redisPassword := viper.GetString("redis.password")
		redisDatabase := viper.GetInt("redis.database")

		redisDb = redis.NewClient(&redis.Options{
			Addr:     redisAddress,
			Password: redisPassword,
			DB:       redisDatabase,
		})
	}

	sessionDuration, err = time.ParseDuration(viper.GetString("sessionDuration"))
	if err != nil {
		log.Fatal(err)
	}

	localCache = cache.New(sessionDuration, 10*time.Minute)

	// this is a global... might be a bad idea
	hmacSecretFile := viper.GetString("hmacSecret")
	hmacSecret = hmacInit(hmacSecretFile)
	runSecure := viper.GetBool("runSecure")

	passwordMap = make(map[string]string)

	// load up the user config for logins
	err = LoadUserConf(userConf)
	if err != nil {
		log.Fatal(err)
	}

	cookieKeys := GetCookieKeys(cookieKeyFile)
	sCookie = securecookie.New([]byte(cookieKeys[0]), []byte(cookieKeys[1]))

	r := mux.NewRouter()
	// this one function will be outside the auth check
	r.HandleFunc("/login", UserLoginHandler).Methods("POST")
	r.HandleFunc("/testsession", TestSessionHandler).Methods("POST")

	loggedRouter := handlers.LoggingHandler(os.Stdout, r)
	log.Printf("Listening at %s\n", listenPort)
	if runSecure {
		// Bind to a port and pass our router in -- this takes in files
		log.Fatal(http.ListenAndServeTLS(listenPort, serverCert, serverKey, loggedRouter))
	} else {
		log.Fatal(http.ListenAndServe(listenPort, loggedRouter))
	}
}
