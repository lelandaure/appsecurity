package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/lelandaure/appsecurity/db"
	"github.com/lelandaure/appsecurity/token"
	"github.com/lelandaure/appsecurity/util"
)

// Server serves HTTP requests for our banking service.
type Server struct {
	config     util.Config
	connection db.Connection
	tokenMaker token.IToken
	router     *gin.Engine
}

func NewServer(config util.Config, conection db.Connection) (*Server, error) {

	//tokenMaker, err := token.NewJWTMaker(config.TokenSymmetricKey)
	tokenMaker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %w", err)
	}

	server := &Server{
		config:     config,
		connection: conection,
		tokenMaker: tokenMaker,
	}

	server.setupRouter()
	return server, nil
}

func (server *Server) setupRouter() {
	router := gin.Default()

	router.POST("/api/auth", server.loginUser)

	server.router = router
}

// Start runs the HTTP server on a specific address.
func (server *Server) Start(address string) error {
	return server.router.Run(address)
}

func errorResponse(err error) gin.H {
	return gin.H{"error": err.Error()}
}
