package sql

import (
	"log"
	"os"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// done here
var Global_db *sqlx.DB

const REFRESH_LIFETIME = 2592000

func Init() {
	if gin.IsDebugging() {
		err := godotenv.Load("../../.env")
		if err != nil {
			log.Println(err)
		}
	}
	dbURL := "postgres://" + os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASSWORD") + "@" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + "/" + os.Getenv("DB_NAME") + "?sslmode=disable"
	Global_db, _ = sqlx.Connect("postgres", dbURL)
	Global_db.SetMaxOpenConns(100)
}
func InsertRefreshToken(hash []byte, jti string, currentTimeStamp time.Time) {
	builder := squirrel.Insert("refresh_tokens").Columns("jti", "token", "exp_date").Values(jti, hash, currentTimeStamp.Add(REFRESH_LIFETIME*time.Second).Format(time.RFC3339)).PlaceholderFormat(squirrel.Dollar)
	str, args, err := builder.ToSql()
	if err != nil {
		log.Println(err)
	}
	_, err = Global_db.Exec(str, args...)
	if err != nil {
		log.Println(err)
	}
}
func DeleteRefreshToken(refreshToken []byte) {
	builder := squirrel.Delete("refresh_tokens").Where(squirrel.Eq{"token ": refreshToken}).PlaceholderFormat(squirrel.Dollar)
	str, args, err := builder.ToSql()
	if err != nil {
		log.Println(err)
	}
	_, err = Global_db.Exec(str, args...)
	if err != nil {
		log.Println(err)
	}
}
func SelectRefreshToken(jti string) ([]byte, string) {
	builder := squirrel.Select("token", "exp_date").From("refresh_tokens").Where(squirrel.Eq{"jti": jti}).PlaceholderFormat(squirrel.Dollar)
	str, args, err := builder.ToSql()
	if err != nil {
		log.Println(err)
	}
	result := Global_db.QueryRow(str, args...)
	var token []byte
	var exp_date string
	result.Scan(&token, &exp_date)
	return token, exp_date
}
