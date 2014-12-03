package go_login

import (
	"log"
	"time"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"crypto/rand"
)

var database *sql.DB

func Init(connectString string){
	db, err := sql.Open("mysql", connectString)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	database = db
	//Set up tables
	_, err = database.Exec("create table if not exist users " +
		"(id unsigned integer primary key auto_increment," +
		" name text not null, email text not null," +
		" password text, salt text, hash text)")
	if err != nil {
		log.Fatal(err)
	}
	_, err = database.Exec("create table if not exist tokens " +
		"(id unsigned integer primary key auto_increment," +
		" issued bigint, expires bigint, userID unsigned integer)")
	if err != nil {
		log.Fatal(err)
	}
}

func Uninit(){
	database.Close()
}

type Password struct {
	Password string//The hashed password
	Salt string//The pseudo-random string used to mitigate dictionary attacks
	Hash string//The cryptographic hashing algorithm used
}

func Authenticate(id uint, password string) bool {
	pswdstmt, err := database.Prepare("select password, salt, hash, id from users where id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer pswdstmt.Close()
	var pswd Password
	err = pswdstmt.QueryRow(id).Scan(&pswd.Password, &pswd.Salt, &pswd.Hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return false//doesn't exist.
		}
		log.Fatal(err)
	}
	var pswdInput []byte
	switch pswd.Hash {
		case "bcrypt20"://bcrypt with a cost of 20
			pswdInput, err = bcrypt.GenerateFromPassword([]byte(password + pswd.Salt), 20)
			if err != nil {
				log.Fatal(err)
			}
		default:
			log.Println("Didn't recognize hash")
			return false
	}
	if pswd.Password == string(pswdInput) {
		return true
	}
	return false
}

type User struct {
	Id uint 
	Name string
	Email string
}

func GetUser(id uint) User {
	var user User
	if id == 0 {
		return user;
	}
	userstmt, err := database.Prepare("select name, email from users where id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer userstmt.Close()
	if err = userstmt.QueryRow(id).Scan(&user.Name, &user.Email); err != nil {
		if err != sql.ErrNoRows {
			log.Panic(err)
		}
		return user
	}
	user.Id = id
	return user
}

func UpdateName(id uint, name string) {
	if id == 0 {
		return	
	}
	updtstmt, err := database.Prepare("update users set name = ? where id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer updtstmt.Close()
	if _, err := updtstmt.Exec(name, id); err != nil {
		log.Fatal(err)
	}
}

func UpdateEmail(id uint, email string) {
	if id == 0 {
		return	
	}
	updtstmt, err := database.Prepare("update users set email = ? where id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer updtstmt.Close()
	if _, err := updtstmt.Exec(email, id); err != nil {
		log.Fatal(err)
	}
}

func UpdatePassword (id uint, password string) {
	if id == 0 {
		return
	}
	//Make a salt
	salt := make([]byte, 128)//Allocate the memory
	_, err := rand.Read(salt)//Populate with random
	if err != nil {
		log.Fatal(err)
	}
	//Append onto password
	password = password + string(salt)
	//Generate the hash
	hashedpswd, err := bcrypt.GenerateFromPassword([]byte(password), 20)
	if err != nil {
		log.Fatal(err)
	}
	//Update the password in the database
	stmt, err := database.Prepare("update users set password = ?, salt = ?, hash = ? where id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	if _, err := stmt.Exec(hashedpswd, string(salt), "bcrypt20", id); err != nil {
		log.Fatal(err)
	}
}

func CreateUser (user User, password string) uint {
	stmt, err := database.Prepare("insert into users (name, email) values (?, ?)")//Going to use update password
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	res, err := stmt.Exec(user.Name, user.Email)
	if err != nil {
		log.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		log.Fatal(err)
	}
	go UpdatePassword(uint(id), password)
	return uint(id)
}

type Token struct {
	Id uint
	Token string
	Issued int64
	Expiry int64
	UserID uint
}

func IssueToken (userID uint, duration int64) Token {
	var token Token
	token.UserID = userID
	now := time.Now().Unix()
	token.Issued = now
	token.Expiry = now + duration
	//Generate token
	tokenStr := make([]byte, 128)
	if _, err := rand.Read(tokenStr); err != nil {
		log.Fatal(err)
	}
	token.Token = string(tokenStr)
	//Add token to database
	stmt, err := database.Prepare("insert into tokens (token, issued, expiry, userID) values (?,?,?,?)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	res, err := stmt.Exec(token.Token, token.Issued, token.Expiry, token.UserID)
	if err != nil {
		log.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		log.Fatal(err)
	}
	token.Id = uint(id)
	return token
}

func Login (email string, password string) Token {
	//Find the user
	stmt, err := database.Prepare("select id from users where email = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	var id uint
	if err = stmt.QueryRow(email).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			var token Token 
			return token//Return an empty token
		}
		log.Fatal(err)
	}
	if Authenticate(id, password) {
		return IssueToken(id, 60*60*2)//Give a 2 hour token
	}
	var token Token
	return token
}
