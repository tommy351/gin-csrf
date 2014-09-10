# gin-csrf

[![Build Status](https://travis-ci.org/tommy351/gin-csrf.svg?branch=master)](https://travis-ci.org/tommy351/gin-csrf)

CSRF protection middleware for [Gin]. This middleware has to be used with [gin-sessions].

## Installation

``` bash
$ go get github.com/tommy351/gin-csrf
```

## Usage

``` go
import (
    "errors"
    
    "github.com/gin-gonic/gin"
    "github.com/tommy351/gin-sessions"
    "github.com/tommy351/gin-csrf"
)

func main(){
    g := gin.New()
    store := sessions.NewCookieStore([]byte("secret123"))
    g.Use(sessions.Middleware("my_session", store))
    g.Use(csrf.Middleware(csrf.Options{
        Secret: "secret123",
        ErrorFunc: func(c *gin.Context){
            c.Fail(400, errors.New('CSRF token mismatch'))
        },
    }))
    
    g.GET("/protected", func(c *gin.Context){
        c.String(200, csrf.GetToken(c))
    })
    
    g.POST("/protected", func(c *gin.Context){
        c.String(200, "CSRF token is valid")
    })
}
```

[Gin]: http://gin-gonic.github.io/gin/
[gin-sessions]: https://github.com/tommy351/gin-sessions