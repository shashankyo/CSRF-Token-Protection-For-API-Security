package main

import(
	
	"log"
	"github.com/shashank/golang-csrf-project/db"
	"github.com/shashank/golang-csrf-project/server"
	"github.com/shashank/golang-csrf-project/server/middleware/myJwt"

var host = "localhost"
var port = "9000"

)

func main() {
	db.InitDB()

	jwtErr := myJwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initializing the jwt")
		log.Fatal(jwtErr)
	}


	serverErr := server.StartServer(host,port)

	if serverErr != nil {
		log.Println("Error starting server!")
		log.Fatal(serverErr)
	}

}
