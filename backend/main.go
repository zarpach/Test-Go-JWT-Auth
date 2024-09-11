package main

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/beevik/guid"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	gomail "gopkg.in/mail.v2"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	accessTokenMaxAge  = 10 * time.Minute
	refreshTokenMaxAge = time.Hour
)

func connect() (*sql.DB, error) {
	bin, err := os.ReadFile("/run/secrets/db-password")
	if err != nil {
		return nil, err
	}
	return sql.Open("postgres", fmt.Sprintf("postgres://postgres:%s@db:5432/example?sslmode=disable", string(bin)))
}

type UserClaims struct {
	GUID     string `json:"guid"`
	Username string `json:"username"`
	Password string `json:"password"`
	IpAddr   string `json:"ipaddr"`
	jwt.Claims
}

type RefreshToken struct {
	Token    string    `json:"token"`
	Expiry   time.Time `json:"expiry"`
	TokenId  string    `json:"token_id"`
	ClientIP string    `json:"client_ip"`
}

func GenerateJWTPair(userId string) (string, RefreshToken, error) {
	TokenId := guid.New().String()
	ClientIP, err := GetLocalIP()

	if err != nil {
		return "", RefreshToken{}, err
	}

	AccessTokenString := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"token_id":  TokenId,
		"user_id":   userId,
		"exp":       time.Now().Add(accessTokenMaxAge).Unix(),
		"client_ip": ClientIP,
	})

	AccessToken, err := AccessTokenString.SignedString([]byte(os.Getenv("KEY")))

	if err != nil {
		return "", RefreshToken{}, err
	}

	CustomRefreshToken := generateRefreshToken(TokenId, ClientIP)

	return AccessToken, CustomRefreshToken, nil
}

func generateRefreshToken(tokenId, clientIp string) RefreshToken {
	token := make([]byte, 48, 64)
	rand.Read(token)

	refreshToken := RefreshToken{
		Token:    string(token),
		Expiry:   time.Now().Add(refreshTokenMaxAge),
		TokenId:  tokenId,
		ClientIP: clientIp,
	}
	return refreshToken
}

func hashToken(token string) (string, error) {
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)

	if err != nil {
		return "", err
	}

	return string(tokenHash), nil
}

func encodeToken(token string) string {
	encodedHash := base64.StdEncoding.EncodeToString([]byte(token))
	return encodedHash
}

func validateToken(refreshTokenHash, refreshTokenString string) error {
	decodedToken, err := base64.StdEncoding.DecodeString(refreshTokenHash)
	err = bcrypt.CompareHashAndPassword([]byte(refreshTokenString), decodedToken)

	if err != nil {
		return err
	}

	return nil
}

func saveRefreshTokenToDB(GUID string, refreshToken string, tokenId string, clientIp string) {
	db, err := connect()

	if err != nil {
		log.Fatal(err)
	}

	insertQuery :=
		`INSERT INTO RefreshTokens(user_guid, refresh_token_hash, token_id, client_ip) 
		 VALUES ($1, $2, $3, $4) ON CONFLICT (user_guid) 
		 DO UPDATE SET user_guid = $1, refresh_token_hash = $2, token_id = $3, client_ip = $4`

	_, err = db.Exec(insertQuery, GUID, refreshToken, tokenId, clientIp)

	if err != nil {
		panic(err)
	}
}

//TIP To run your code, right-click the code and select <b>Run</b>. Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World %s", r.URL.Path[1:])
}

func access(w http.ResponseWriter, r *http.Request) {
	GUID := r.URL.Query().Get("GUID")
	if !guid.IsGuid(GUID) {
		fmt.Fprint(w, "No GUID provided")
		return
	}

	accessToken, customRefreshToken, err := GenerateJWTPair(GUID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshToken, _ := hashToken(customRefreshToken.Token)
	saveRefreshTokenToDB(GUID, refreshToken, customRefreshToken.TokenId, customRefreshToken.ClientIP)

	accessTokenCookie := &http.Cookie{
		Name:    "AccessToken",
		Value:   accessToken,
		Expires: time.Now().Add(accessTokenMaxAge)}
	refreshTokenCookie := &http.Cookie{
		Name:    "RefreshToken",
		Value:   encodeToken(customRefreshToken.Token),
		Expires: time.Now().Add(refreshTokenMaxAge)}

	http.SetCookie(w, accessTokenCookie)
	http.SetCookie(w, refreshTokenCookie)

	fmt.Fprintf(w, "Access: %s\n", accessToken)
	fmt.Fprintf(w, "Refresh: %s\n", encodeToken(customRefreshToken.Token))
}

func refresh(w http.ResponseWriter, r *http.Request) {
	GUID := r.URL.Query().Get("GUID")

	if !guid.IsGuid(GUID) {
		fmt.Fprint(w, "No GUID provided")
		return
	}

	accessTokenString, _ := r.Cookie("AccessToken")
	refreshTokenHash, _ := r.Cookie("RefreshToken")

	if len(refreshTokenHash.Value) <= 0 {
		fmt.Fprint(w, "No refresh token provided")
		return
	}

	ParsedAccessToken, _ := jwt.Parse(accessTokenString.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("KEY")), nil
	})

	db, err := connect()
	var (
		refreshTokenString string
		refreshTokenId     string
	)
	rows, err := db.Query("SELECT refresh_token_hash, token_id FROM RefreshTokens WHERE user_guid = $1", GUID)

	if err != nil {
		panic(err)
	}

	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			panic(err)
		}
	}(rows)

	for rows.Next() {
		err := rows.Scan(&refreshTokenString, &refreshTokenId)
		if err != nil {
			panic(err)
		}
	}
	err = rows.Err()
	if err != nil {
		panic(err)
	}

	err = validateToken(refreshTokenHash.Value, refreshTokenString)
	if err != nil {
		fmt.Fprintf(w, "invalid token: %s", err.Error())
		return
	}

	if !IsTokenPairMutual(ParsedAccessToken, refreshTokenId) {
		fmt.Fprint(w, "Tokens are not mutually connected!")
		return
	}

	if IpHaveChanged(GUID) {
		sendWarningEmail()
	}

	AccessToken, CustomRefreshToken, err := GenerateJWTPair(GUID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	hashedRefreshToken, err := hashToken(CustomRefreshToken.Token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	saveRefreshTokenToDB(GUID, hashedRefreshToken, CustomRefreshToken.TokenId, CustomRefreshToken.ClientIP)

	fmt.Fprintf(w, "Access: %s\n", AccessToken)
	fmt.Fprintf(w, "Refresh: %s\n", encodeToken(CustomRefreshToken.Token))
}

func GetLocalIP() (string, error) {
	var ip net.IP
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addresses {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP
			}
		}
	}
	return ip.String(), nil
}

func IpHaveChanged(GUID string) bool {
	ip, err := GetLocalIP()

	if err != nil {
		log.Fatal(err)
	}

	db, err := connect()

	if err != nil {
		log.Fatal(err)
	}

	var row string
	err = db.QueryRow("SELECT client_ip FROM RefreshTokens WHERE user_guid = $1", GUID).Scan(&row)

	if err != nil {
		log.Fatal(err)
	}

	return !strings.EqualFold(row, ip)
}

func sendWarningEmail() {
	m := gomail.NewMessage()

	m.SetHeader("From", "sanazera2@gmail.com")
	m.SetHeader("To", "erokuza97@gmail.com")
	m.SetHeader("Subject", "Warning! Your IP have changed!")

	m.SetBody("text/plain",
		"It's <company name> team. "+
			"We detected suspicious behaviour on your account. "+
			"Your IP address have changed."+
			"If it was you, please ignore this message.")

	d := gomail.NewDialer("smtp.gmail.com", 587, "sanazera2@gmail.com", "kfik fgpo aiyz qdda")

	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		fmt.Println(err)
		panic(err)
	}
}

func IsTokenPairMutual(accessToken *jwt.Token, refreshTokenId string) bool {
	return accessToken.Claims.(jwt.MapClaims)["token_id"] == refreshTokenId
}

func main() {
	err := os.Setenv("KEY", "StrongKey")
	if err != nil {
		return
	}

	log.Print("Prepare db...")
	if err := prepareDB(); err != nil {
		log.Fatal(err)
	}

	log.Print("DB is ready!")
	http.HandleFunc("/access", access)
	http.HandleFunc("/refresh", refresh)

	log.Fatal(http.ListenAndServe(":8000", nil))
}

func prepareDB() error {
	db, err := connect()

	if err != nil {
		return err
	}

	defer db.Close()

	for i := 0; i < 60; i++ {
		if err := db.Ping(); err == nil {
			break
		}
		time.Sleep(time.Second)
	}

	if _, err := db.Exec("DROP TABLE IF EXISTS RefreshTokens;"); err != nil {
		return err
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS RefreshTokens (
    id bigint NOT NULL GENERATED ALWAYS AS IDENTITY (INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 10000000000 CACHE 1),
    user_guid text COLLATE pg_catalog."default" UNIQUE,
    refresh_token_hash text COLLATE pg_catalog."default",
    used boolean DEFAULT false,
    token_id text COLLATE pg_catalog."default",
    client_ip text COLLATE pg_catalog."default",
    PRIMARY KEY (id)
);`); err != nil {
		return err
	}

	return nil
}

//TIP See GoLand help at <a href="https://www.jetbrains.com/help/go/">jetbrains.com/help/go/</a>.
// Also, you can try interactive lessons for GoLand by selecting 'Help | Learn IDE Features' from the main menu.
