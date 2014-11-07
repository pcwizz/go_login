package go_login

import (
	"database/sql",
	"github.com/go-sql-driver/mysql"
	"time"
)


// Email address

//They can be active or in active not just strings
type email struct {
	email string
	Active bool
}
//A user may have more than one
type emails []email;

//Passwords
//We need to know which cryptographic hashing algorithm we used,
//because it will change as computers get more powerful, so we
//need to think ahead.
//We also need to know the salt; salt makes everything better 
//(apart from human health).
//We don't like manipulating strings when we don't have to.
type password struct {
	Password string
	Salt string
	Hash string
}

//Permissions
//We could just use an enum, but then we would have to change this 
//for just about every application we write using it; I'm lazy.
type permission struct {
	Id const int
	Description string
}

type permissions []permission

//Groups
//Modelling the inheritance hirarchy of our groups in code is silly,
//we are more concerned about cpu time than memory, the database can
//provide abstraction; the database will do a better job than me.

type group struct {
	Name string
	Description string
	Permissions permissions
}

type groups []group

//Tokens
//For ****'s sake give them expiry dates, then check the hole thing.
//We don't give a **** about when we gave out a token, I put it in 
//the db for a clear audit trail.
type token struct {
	Token string
	Expires Time
}

//Users
type user struct {
	Id const int
	Username string
	Password password
	Active bool
	Emails emails
	Groups groups //users can have more than one group; might be useful.
}

//Sessions (login tokens)
type session struct {
	User *user
	Token token
}

