package crypto

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// guess done here nothing to add
var SignatureMethod = jwt.SigningMethodHS512

const MAIL = "mockmock@mock.mock"
const ACCESS_LIFETIME = 1800

type Claims struct {
	Guid        string
	Jti         string
	Ip          string
	Mail        string
	Expire_date string
}

func EncodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}
func DecodeSegment(str string) string {
	unparsed, err := base64.RawStdEncoding.DecodeString(str)
	if err != nil {
		log.Println(err)
	}
	return string(unparsed)
}
func splitAccessToken(token string) []string {
	var a []string = strings.Split(token, ".")
	return a
}
func CheckAccessSignature(token string) bool {
	var SECRET = os.Getenv("SECRET_KEY")
	parts := splitAccessToken(token)
	verif, err := SignatureMethod.Sign(parts[0]+"."+parts[1], []byte(SECRET))
	if err != nil {
		log.Println(err)
	}
	if EncodeSegment(verif) == parts[2] {
		return true
	} else {
		return false
	}
}
func GetClaimsFromToken(token string) Claims {
	parts := splitAccessToken(token)
	var result Claims
	body := DecodeSegment(parts[1])
	err := json.Unmarshal([]byte(body), &result)
	if err != nil {
		log.Println(err)
	}
	return result
}
func BcryptHashGenerate(token string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
	}
	return hash
}
func GenerateJWT(guid string, ip string, currentTimeStamp time.Time) (string, string) {
	jti := uuid.NewString()
	var SECRET = os.Getenv("SECRET_KEY")
	payload := jwt.MapClaims{"guid": guid, "jti": jti, "ip": ip, "mail": MAIL, "expire_date": currentTimeStamp.Add(ACCESS_LIFETIME * time.Second).Format(time.RFC3339)}
	token := jwt.NewWithClaims(SignatureMethod, payload)
	accessToken, err := token.SignedString([]byte(SECRET))
	if err != nil {
		log.Println(err)
	}
	return accessToken, jti
}

type TokenHash struct {
	Token string
	Hash  []byte
}

func GenerateRefreshToken(init <-chan struct{}, buffer chan<- TokenHash) {
	//rewrite to make it stable coroutine for worker pool
	for sema := range init {

		refreshToken := uuid.NewString()
		hash := BcryptHashGenerate(refreshToken)
		refreshToken = base64.RawStdEncoding.Strict().EncodeToString([]byte(refreshToken))
		buffer <- TokenHash{refreshToken, hash}
	}
}
