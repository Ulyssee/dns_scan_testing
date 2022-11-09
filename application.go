package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"errors"
	"io"
	"strings"

	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"
	"github.com/didip/tollbooth/v6"
	"github.com/didip/tollbooth/v6/limiter"
	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"

	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/domainadvisor"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/model"
)

///////////////////////////Server///////////////////////////

// Server represents an HTTP server. It is meant to wrap all HTTP functionality
// used by the application so that dependent packages (such as cmd/wtfd) do not
// need to reference the "net/http" package at all.
type Server struct {
	handler http.Handler
	lmt     *limiter.Limiter
	ln      net.Listener
	logger  zerolog.Logger
	server  *http.Server
	router  *gin.Engine

	Routes *gin.RouterGroup

	// Bind address & domain for the server's listener.
	Addr string

	// Services used by the various HTTP routes.
	Scanner *scanner.Scanner
}

/*
	func test() {
		server := gin.Default()
		server.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "pong",
			})
		})

}
*/

func main() {

	rateLimiter := tollbooth.NewLimiter(10, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	rateLimiter.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"}).
		SetMethods([]string{"GET", "POST"})

	s := &Server{
		handler: nil,
		lmt:     rateLimiter,
		ln:      nil,
		server:  &http.Server{},
		router:  gin.New(),
		Routes:  &gin.RouterGroup{},
		Addr:    "",
		Scanner: &scanner.Scanner{},
	}

	//route ping pour tester le serveur qui retourne pong
	s.router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	//route scan/:domain qui retourne un json avec les infos du domaine
	s.router.GET("/api/v1/scan/:domain", func(c *gin.Context) {
		domain := c.Param("domain")

		if queryParam, ok := c.GetQuery("dkimSelector"); ok {
			s.Scanner.DKIMSelector = queryParam
		}

		if queryParam, ok := c.GetQuery("recordType"); ok {
			s.Scanner.RecordType = queryParam
		}

		result := s.Scanner.Scan(domain)
		print("passed")
		advice := domainadvisor.CheckAll(result.SPF, result.DMARC, result.BIMI, result.DKIM)

		resultWithAdvice := model.ScanResultWithAdvice{
			ScanResult: result,
			Advice:     advice,
		}

		s.respond(c, 200, &resultWithAdvice)
	})

	s.router.POST("/api/v1/scan", func(c *gin.Context) {
		var domains []string
		if err := c.BindJSON(&domains); err != nil {
			s.respond(c, 400, err)
			return

		}

		if len(domains) == 0 {
			s.respond(c, 400, errors.New("no domains provided"))
			return
		}

		if queryParam, ok := c.GetQuery("dkimSelector"); ok {
			s.Scanner.DKIMSelector = queryParam

		}

		if queryParam, ok := c.GetQuery("recordType"); ok {
			s.Scanner.RecordType = queryParam
		}

		results := make([]model.ScanResultWithAdvice, len(domains))
		for i, domain := range domains {
			result := s.Scanner.Scan(domain)
			advice := domainadvisor.CheckAll(result.SPF, result.DMARC, result.BIMI, result.DKIM)
			results[i] = model.ScanResultWithAdvice{
				ScanResult: result,
				Advice:     advice,
			}
		}

		s.respond(c, 200, &results)
	})

	s.router.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"message": "not found"})
	})

	s.handler = cors.Default().Handler(s.router)
	s.Serve(8080)
}

// NewServer returns a new instance of Server.
func NewServer(logger zerolog.Logger) *Server {
	gin.SetMode(gin.ReleaseMode)

	rateLimiter := tollbooth.NewLimiter(10, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	rateLimiter.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"}).
		SetMethods([]string{"GET", "POST"})

	// Create a new server that wraps the net/http server & add a gin router.
	s := &Server{
		handler: nil,
		lmt:     rateLimiter,
		ln:      nil,
		logger:  logger,
		server:  &http.Server{},
		router:  gin.New(),
		Routes:  &gin.RouterGroup{},
		Addr:    "5000",
		Scanner: &scanner.Scanner{},
	}

	s.router.Use(gin.Logger(), gin.Recovery())

	// Setup error handling routes.
	s.router.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"message": "not found"})
	})

	v1 := s.router.Group("/api/v1")
	v1.Use(s.handleRateLimit(s.lmt))

	// Register unauthenticated routes.
	{
		s.Routes = v1.Group("")
		s.registerScanRoutes(s.Routes)
	}

	// enable CORS support
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowCredentials: false,
		Debug:            false,
	})

	s.handler = c.Handler(s.router)

	return s
}

func (s *Server) Serve(port int) {
	portString := cast.ToString(port)

	s.logger.Info().Msg("Starting api server on port " + portString)
	s.logger.Fatal().Err(http.ListenAndServe("0.0.0.0:"+portString, s.handler)).Msg("an error occurred while hosting the api server")
}

func (s *Server) handleRateLimit(lmt *limiter.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		httpError := tollbooth.LimitByRequest(lmt, c.Writer, c.Request)
		if httpError != nil {
			c.Writer.Header().Set("Content-Type", "application/json")
			c.Writer.WriteHeader(429)
			data := map[string]string{"message": "too many requests"}
			if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
				s.logger.Error().Err(err)
			}
			c.Abort()
			return
		} else {
			c.Next()
		}
	}
}

func (s *Server) respond(c *gin.Context, code int, data interface{}) {
	if code/100 == 4 || code/100 == 5 {
		text := fmt.Sprintf("%v", data)
		data = map[string]string{"message": text}
	}

	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(code)
	if code != 204 {
		if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
			s.logger.Fatal().Err(err).Msg("Failed to encode json object")
		}
	}
}

type bulkDomainRequest struct {
	Domains []string `json:"domains"`
}

func (s *Server) registerScanRoutes(r *gin.RouterGroup) {
	r.GET("/scan/:domain", s.handleScanDomain)
	r.POST("/scan", s.handleScanDomains)
}

func (s *Server) handleScanDomain(c *gin.Context) {
	domain := c.Param("domain")

	if queryParam, ok := c.GetQuery("dkimSelector"); ok {
		s.Scanner.DKIMSelector = queryParam
	}

	if queryParam, ok := c.GetQuery("recordType"); ok {
		s.Scanner.RecordType = queryParam
	}

	result := s.Scanner.Scan(domain)
	advice := domainadvisor.CheckAll(result.SPF, result.DMARC, result.BIMI, result.DKIM)

	resultWithAdvice := model.ScanResultWithAdvice{
		ScanResult: result,
		Advice:     advice,
	}

	s.respond(c, 200, &resultWithAdvice)
}

func (s *Server) handleScanDomains(c *gin.Context) {
	var domains bulkDomainRequest

	if err := Decode(c, &domains); err != nil {
		s.logger.Error().Err(err).Msg("error occurred during handleScanDomains request")
		s.respond(c, 400, "you need to supply an array of domains in the body of the request, formatted as json")
		return
	}

	// mitigate potential abuse
	if len(domains.Domains) > 20 {
		s.respond(c, 400, "you cannot bulk process more than 20 domains at a time")
		return
	}

	domainList := strings.NewReader(strings.Join(domains.Domains, "\n"))
	source := scanner.TextSource(domainList)

	if queryParam, ok := c.GetQuery("dkimSelector"); ok {
		s.Scanner.DKIMSelector = queryParam
	}

	if queryParam, ok := c.GetQuery("recordType"); ok {
		s.Scanner.RecordType = queryParam
	}

	var resultsWithAdvice []model.ScanResultWithAdvice

	for result := range s.Scanner.Start(source) {
		advice := domainadvisor.CheckAll(result.SPF, result.DMARC, result.BIMI, result.DKIM)
		resultsWithAdvice = append(resultsWithAdvice, model.ScanResultWithAdvice{
			ScanResult: result,
			Advice:     advice,
		})
	}

	s.respond(c, 200, resultsWithAdvice)
}

func (s *Server) handlePing(c *gin.Context) {
	s.respond(c, 200, "pong")
}

///////////////////////////Handler///////////////////////////

func Decode(c *gin.Context, object interface{}) error {
	if !strings.Contains(c.Request.Header.Get("Content-type"), "application/json") {
		return errors.New("only application/json is supported")
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1048576)

	if err := c.BindJSON(&object); err != nil {
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError

		switch {
		case errors.As(err, &syntaxError):
			return errors.New("request body contains badly-formed JSON (at position " + cast.ToString(syntaxError.Offset) + ")")
		case errors.Is(err, io.ErrUnexpectedEOF):
			return errors.New("request body contains badly-formed JSON")
		case errors.As(err, &unmarshalTypeError):
			return errors.New("request body contains an invalid value for the " + unmarshalTypeError.Field + " field (at position " + cast.ToString(unmarshalTypeError.Offset) + ")")
		case errors.Is(err, io.EOF):
			return errors.New("request body must not be empty")
		case err.Error() == "http: request body too large":
			return errors.New("request body must not be larger than 1MB")
		default:
			return err
		}
	}
	return nil
}
