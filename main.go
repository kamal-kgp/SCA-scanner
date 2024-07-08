package main

import (
	"github.com/gofiber/fiber/v2"
	"sca/controllers"
)

func main() {

	app := fiber.New()

	app.Post("/upload", controllers.HandleRequest)
	
	// Start the Fiber server
	app.Listen(":3000")
}

