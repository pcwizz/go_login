# Go login
## Abstracting login via a package

### Features
- Password based login using bcypt
- mysql back end

### TODO
- Client certificate authentication [] 
	- Move password fields of of users table [x]
	- Write the functions []
- Create tests []
- Caching (database persistence)

### Usage
To use the package, you should run the Init function -provide it with a connection string for you db-, this will make sure the tables it needs are set up and stores a un-exported \*sql.DB object that most of the functions in the package rely on.

### License
This project is under a GPLv3 licence, a copy of the license can be found [here](LICENSE).
