package gmail

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"

	"code.google.com/p/goauth2/oauth"
)

const (
	clientID     = "662253522071.apps.googleusercontent.com"
	clientSecret = "stmfkXkldECvcHSa0A7Z8ZpE"
	scope        = "https://mail.google.com/"
	authURL      = "https://accounts.google.com/o/oauth2/auth"
	tokenURL     = "https://accounts.google.com/o/oauth2/token"
)

type Conn struct {
	user  string
	cache oauth.CacheFile
	token *oauth.Token
	tconn *textproto.Conn
}

func NewConn(user, cacheFile string) *Conn {
	return &Conn{user: user, cache: oauth.CacheFile(cacheFile)}
}

type ErrAuthRedirect string

func (e ErrAuthRedirect) Error() string {
	return "redirect for auth to " + string(e)
}

func (e ErrAuthRedirect) Redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, string(e), http.StatusSeeOther)
}

func (c *Conn) Auth(done func(http.ResponseWriter, *http.Request)) error {
	if c.token != nil {
		return nil
	}
	tok, err := c.cache.Token()
	if err == nil && !tok.Expired() {
		log.Printf("Using cached token %v", tok)
		c.token = tok
		return nil
	}

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return err
	}
	// It's important for it to be of the form "localhost:port" for OAuth.
	addr := fmt.Sprintf("localhost:%d", l.Addr().(*net.TCPAddr).Port)
	log.Printf("Listening on %s for auth redirect...", addr)

	config := &oauth.Config{
		ClientId:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		RedirectURL:  fmt.Sprintf("http://%s/authredir", addr),
		TokenCache:   c.cache,
		// AccessType: "online",
	}

	// TODO: timeout here somewhere.

	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authredir" {
			http.NotFound(w, r)
			return
		}
		defer done(w, r)
		defer l.Close()
		defer log.Printf("Finished auth redirect listening on %s", addr)

		code := r.FormValue("code")

		trans := &oauth.Transport{Config: config}
		tok, err := trans.Exchange(code)
		if err != nil {
			// TODO: or maybe a sticky error?
			log.Printf("OAuth failure: %v", err)
			time.Sleep(5 * time.Second)
			return
		}
		c.token = tok
	}))

	return ErrAuthRedirect(config.AuthCodeURL(""))
}

func (c *Conn) Start() error {
	if c.token == nil {
		return errors.New("Auth not done")
	}
	authString := fmt.Sprintf("user=%s\001auth=Bearer %s\001\001", c.user, c.token.AccessToken)
	enc := base64.StdEncoding.EncodeToString([]byte(authString))

	conn, err := tls.Dial("tcp", "imap.gmail.com:993", nil)
	if err != nil {
		return fmt.Errorf("tls.Dial: %v", err)
	}
	c.tconn = textproto.NewConn(conn)

	resp, untagged, err := c.cmdf("CAPABILITY")
	if err != nil {
		log.Printf("CAP: %v (%#v)", resp, untagged)
		return fmt.Errorf("getting IMAP capabilities: %v", err)
	}

	resp, untagged, err = c.cmdf("AUTHENTICATE XOAUTH2 %s", enc)
	if err != nil {
		return fmt.Errorf("authenticating: %v", err)
	}
	if !strings.HasPrefix(resp, "OK") {
		log.Printf("AUTH: %v (%#v)", resp, untagged)
		return fmt.Errorf("auth failed: %v", resp)
	}

	return nil
}

func (c *Conn) Select(box string) error {
	resp, _, err := c.cmdf("SELECT %q", box)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("SELECT failed: %v", resp)
	}
	return nil
}

func protocolf(server bool, format string, args ...interface{}) {
	pre := map[bool]string{true: "\033[32;1m", false: "\033[32m"}
	fmt.Fprintf(os.Stderr, pre[server]+format+"\033[0m\n", args...)
}

// TODO: kill this
func (c *Conn) Rawf(format string, args ...interface{}) (response string, untagged []string, err error) {
	return c.cmdf(format, args...)
}

func (c *Conn) cmdf(format string, args ...interface{}) (response string, untagged []string, err error) {
	id := c.tconn.Next()
	c.tconn.StartRequest(id)
	raw := fmt.Sprintf(format, args...)
	tag := fmt.Sprintf("A%03d ", id)
	protocolf(false, "C: %s%s", tag, raw)
	if err = c.tconn.PrintfLine("%s%s", tag, raw); err != nil {
		return
	}
	c.tconn.EndRequest(id)
	c.tconn.StartResponse(id)
	defer c.tconn.EndResponse(id)
	for {
		response, err = c.tconn.ReadLine()
		if err != nil {
			return
		}
		protocolf(true, "S: %s", response)
		if strings.HasPrefix(response, "*") {
			untagged = append(untagged, strings.TrimSpace(response[1:]))
			continue
		}
		if strings.HasPrefix(response, "+") { // HACK HACK HACK: for AUTH!
			c.tconn.PrintfLine("")
			continue
		}
		if !strings.HasPrefix(response, tag) {
			err = fmt.Errorf("got %q when looking for tag %q", response, tag)
			return
		}
		response = response[len(tag):]
		break
	}
	return
}
