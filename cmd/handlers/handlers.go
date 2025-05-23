package handlers

import (
	"authgolang/internal/crypto"
	"authgolang/internal/smtpadd"
	"authgolang/internal/sql"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const COOKIE_LIFETIME = 2592000

func GetPair(buffer <-chan crypto.TokenHash) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Query("guid") == "" {
			log.Println(c.ClientIP() + " try to access with no GUID")
			return
		}
		currentTimeStamp := time.Now().UTC()
		refreshPair := <-buffer
		access, jti := crypto.GenerateJWT(c.Query("guid"), c.ClientIP(), currentTimeStamp)
		sql.InsertRefreshToken(refreshPair.Hash, jti, currentTimeStamp)
		insertCookie(access, refreshPair.Token, c)
	}
}

// unreadable, repeated code, need to refactor
func RefreshPair(buffer <-chan crypto.TokenHash) gin.HandlerFunc {

	return func(c *gin.Context) {
		refresh, err := c.Cookie("refresh_token")
		if err != nil {
			log.Println(err)
			return
		}
		access, err := c.Cookie("access_token")
		if err != nil {
			log.Println(err)
			return
		}
		if crypto.CheckAccessSignature(access) { //check signature is ok go next
			accessClaims := crypto.GetClaimsFromToken(access)           //parse claims from JWT
			hash, dbexpdate := sql.SelectRefreshToken(accessClaims.Jti) //find row in db with JTIdentifier
			currentTimeStamp := time.Now().UTC()                        //declare for generate new tokens and check expire date
			timestamp, err := time.Parse(time.RFC3339, dbexpdate)
			if err != nil {
				log.Println(err)
			}
			if currentTimeStamp.After(timestamp) { //if today>expdate break
				return
			}
			err = bcrypt.CompareHashAndPassword(hash, []byte(refresh)) //is refresh token == hash in database?
			if err == nil {                                            //if equal go next
				if accessClaims.Ip != c.ClientIP() {
					smtpadd.SendToEmail(accessClaims.Mail, c.ClientIP()) //send email if curr ip!=claims.Ip
				}
				sql.DeleteRefreshToken(hash) //maybe better make INSERT INTO Have only 1 index on JTI
				refreshPair := <-buffer
				newAccess, jti := crypto.GenerateJWT(accessClaims.Guid, c.ClientIP(), currentTimeStamp) //generate new insert into db
				sql.InsertRefreshToken(refreshPair.Hash, jti, currentTimeStamp)
				insertCookie(newAccess, refresh, c) //set new cookie
			} else {
				log.Println(err)
				return
			}
		} else {
			return
		}
	}
}
func insertCookie(access string, refresh string, c *gin.Context) {
	c.SetCookie("access_token", access, COOKIE_LIFETIME, "/", "", false, true)
	c.SetCookie("refresh_token", refresh, COOKIE_LIFETIME, "/", "", false, true)
}
