package go_login

import (
	//"database/sql",
	//"github.com/go-sql-driver/mysql"
	"time"
)

// Email address

//They can be active or in active not just strings
type email struct {
	Email string
	Active bool
	User *user //Doubling up the links for ease of use.
}
//A user may have more than one
type emails []email;
func activeEmails_h(es emails) emails{
	output := make(emails,0, len(es))
	for i := range es {
		if (es[i].Active){
			output = append(output, es[i])
		}
	}
	return output
}
//We only care about active emails most of the time
func activeEmails(es emails)(emails){
	length := len(es)
	switch length{
		case 0:
			return nil
		case 1:
			if es[0].Active {
				return es
			} else {
				return nil	
			}
		default:
			return activeEmails_h(es)
	}
}


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
	Id int 
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
	Expires time.Time
}

//Users
type user struct {
	Id int
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

type sessions []session


//Login attempts
//Keeping track of failed logins so attacks can be mitigated

type attempt struct {
	Host string
	Time time.Time
	Email email //Who did they try to log in ass, do they even exist
} 

//We will want to keep a time based buffer of these


