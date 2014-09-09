package csrf

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"

	"github.com/dchest/uniuri"
	"github.com/gin-gonic/gin"
	"github.com/tommy351/gin-sessions"
)

const (
	saltKey = "_csrf_salt"
)

var defaultIgnoreMethods = []string{"GET", "HEAD", "OPTIONS"}

var defaultErrorFunc = func(c *gin.Context) {
	panic(errors.New("CSRF token mismatch"))
}

var defaultTokenGetter = func(c *gin.Context) string {
	r := c.Request

	if t := r.FormValue("_csrf"); len(t) > 0 {
		return t
	} else if t := r.URL.Query().Get("_csrf"); len(t) > 0 {
		return t
	} else if t := r.Header.Get("X-CSRF-TOKEN"); len(t) > 0 {
		return t
	} else if t := r.Header.Get("X-XSRF-TOKEN"); len(t) > 0 {
		return t
	}

	return ""
}

type Options struct {
	Secret        string
	IgnoreMethods []string
	ErrorFunc     gin.HandlerFunc
	TokenGetter   func(c *gin.Context) string
}

type CSRF interface {
	GetToken() string
}

type csrf struct {
	secret  string
	token   string
	session sessions.Session
}

func (c *csrf) GetToken() string {
	if len(c.token) == 0 {
		salt := uniuri.New()
		c.token = tokenize(c.secret, salt)
		c.session.Set(saltKey, salt)
		c.session.Save()
	}

	return c.token
}

func tokenize(secret, salt string) string {
	h := sha1.New()
	io.WriteString(h, salt+"-"+secret)
	hash := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return hash
}

func inArray(arr []string, value string) bool {
	inarr := false

	for _, v := range arr {
		if v == value {
			inarr = true
			break
		}
	}

	return inarr
}

func Middleware(options Options) gin.HandlerFunc {
	ignoreMethods := options.IgnoreMethods
	errorFunc := options.ErrorFunc
	tokenGetter := options.TokenGetter

	if ignoreMethods == nil {
		ignoreMethods = defaultIgnoreMethods
	}

	if errorFunc == nil {
		errorFunc = defaultErrorFunc
	}

	if tokenGetter == nil {
		tokenGetter = defaultTokenGetter
	}

	return func(c *gin.Context) {
		var session sessions.Session

		if s, err := c.Get("session"); err != nil {
			panic(errors.New("You have to install gin-sessions middleware"))
		} else {
			session = s.(sessions.Session)
		}

		r := c.Request

		c.Set("csrf", &csrf{
			secret:  options.Secret,
			session: session,
		})

		if inArray(ignoreMethods, r.Method) {
			c.Next()
			return
		}

		var salt string

		if s, ok := session.Get(saltKey).(string); !ok || len(s) == 0 {
			c.Next()
			return
		} else {
			salt = s
		}

		session.Delete(saltKey)

		token := tokenGetter(c)

		if tokenize(options.Secret, salt) != token {
			errorFunc(c)
			return
		}

		c.Next()
	}
}
