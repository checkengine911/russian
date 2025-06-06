package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

var (
	blockList = make(map[string]time.Time)
 	mu sync.Mutex
	store *sessions.CookieStore
	moneyEarned = 0

	adminIPs = map[string]bool {
		"": true,
	}
)

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*.html")
	r.Static("/static", "./static")

	sessionKey := os.Getenv("SESSION_SECRET")
	if sessionKey == "" {
		log.Fatal("Session secret was not loaded.")
		return
	}

	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   true,  // Set to false if not using HTTPS/in development
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7, // 7 days
	}

	r.GET("/", indexHandler)
	r.GET("/gametime", gametimeHandler)
	r.GET("/admin/blocked-ip", adminBlockedIPHandler)
	r.POST("/admin/unblock-ip", adminUnblockIPHandler)
	r.GET("/banned", bannedHandler)
	r.GET("/start-game", startGameHandler)
	r.GET("/cashout", cashoutHandler)
	r.GET("/pregamestart", pregameStartHandler)

	err := r.Run(":6875")
	if err != nil {
		log.Fatal(err)
	}
}

// Admin endpoint to view blocked IPs
func adminBlockedIPHandler(c *gin.Context) {
	mu.Lock()
	defer mu.Unlock()

	// Get multiple IP representations
    userIP := c.ClientIP()

    // Check if the user's IP is in the admin IP list
    if !adminIPs[userIP] {
        c.String(403, fmt.Sprintf("Access denied. Your IP (%s) is not authorized.", userIP))
        return
    }

	// Display blocked IPs
	blocked := make([]string, 0, len(blockList))
	for ip, unblockTime := range blockList {
		blocked = append(blocked, fmt.Sprintf("IP: %s, Blocked Until: %s", ip, unblockTime.Format(time.RFC1123)))
	}

	c.HTML(200, "admin_blocked_ips.html", gin.H{
		"blockedIPs": blocked,
	})
}

// Admin endpoint to unblock a specific IP
func adminUnblockIPHandler(c *gin.Context) {
	mu.Lock()
	defer mu.Unlock()

	// Check if the user's IP is in the admin IP list
	userIP := c.ClientIP()
	if !adminIPs[userIP] {
		c.String(403, "Access denied. Your IP is not authorized.")
		return
	}

	// Get IP to unblock from the form data
	ipToUnblock := c.PostForm("ip")
	if ipToUnblock == "" {
		c.String(400, "Invalid IP address")
		return
	}

	// Remove the IP from the block list
	if _, exists := blockList[ipToUnblock]; exists {
		delete(blockList, ipToUnblock)
		c.String(200, fmt.Sprintf("IP %s has been unblocked.", ipToUnblock))
	} else {
		c.String(404, fmt.Sprintf("IP %s not found in the block list.", ipToUnblock))
	}
}

func indexHandler(c *gin.Context) {
	mu.Lock()
	defer mu.Unlock()

	// Get users ip
	userIP := c.ClientIP()
	// Check if the user is blocked
	if unblockTime, exists := blockList[userIP]; exists {
		if time.Now().Before(unblockTime) {
			c.String(http.StatusUnauthorized, "You lost. Your IP and information is now ours and being sent out. Time to pay up.")
			return
		}
		delete(blockList, userIP)
	}
	c.HTML(200, "index.html", nil)
}

func gametimeHandler(c *gin.Context) {
	fmt.Println("***gametimeHandler running***")
	mu.Lock()
	defer mu.Unlock()

	// Get users ip
	userIP := c.ClientIP()

	// Check if the user is blocked
	if unblockTime, exists := blockList[userIP]; exists {
		if time.Now().Before(unblockTime) {
			c.String(http.StatusUnauthorized, "You lost. Your IP and information is now ours and being sent out. Time to pay up.")
			return
		}
		delete(blockList, userIP)
	}

	// Get session
	session, err := store.Get(c.Request, "game-session")
	if err != nil {
		log.Println("Error getting session:", err)
		c.String(http.StatusInternalServerError, "Internal server error")
		return
	}

	// After saving session
    err = session.Save(c.Request, c.Writer)
    if err != nil {
        log.Println("Session Save Error:", err)
    }

	// Explicitly set values if not exists
    if session.Values["gameStarted"] == nil {
        session.Values["gameStarted"] = false
    }
    if session.Values["userRoll"] == nil {
        session.Values["userRoll"] = 6
    }
    if session.Values["moneyEarned"] == nil {
        session.Values["moneyEarned"] = 0
    }
    if session.Values["timesWon"] == nil {
        session.Values["timesWon"] = 0
    }
    if session.Values["timesSurvived"] == nil {
        session.Values["timesSurvived"] = 0
    }
    if session.Values["attempt"] == nil {
        session.Values["attempt"] = 1
    }
    if session.Values["didUserWin"] == nil {
        session.Values["didUserWin"] = false
    }

    // Explicitly convert to expected types
    gameStarted, _ := session.Values["gameStarted"].(bool)
    userRoll, _ := session.Values["userRoll"].(int)
    moneyEarned, _ = session.Values["moneyEarned"].(int)
    timesWon, _ := session.Values["timesWon"].(int)
    timesSurvived, _ := session.Values["timesSurvived"].(int)
    attempt, _ := session.Values["attempt"].(int)
    didUserWin, _ := session.Values["didUserWin"].(bool)

	log.Printf("gameStarted: %v", gameStarted)

	winMessage := ""
	rand.Seed(time.Now().UnixNano())
	killShot := rand.Intn(6) + 1
	if userRoll == killShot {
		// Block the user for 1140 years aka forever
		blockList[userIP] = time.Now().Add(999999 * time.Hour)
		session, err = store.Get(c.Request, "game-session")
		delete(session.Values, "userRoll")
		delete(session.Values, "moneyEarned")
		delete(session.Values, "timesWon")
		delete(session.Values, "timesSurvived")
		delete(session.Values, "attempt")
		delete(session.Values, "didUserWin")
		delete(session.Values, "gameStarted")
		session.Save(c.Request, c.Writer)
		c.Redirect(http.StatusFound, "/banned")
	} else {
		// Survived round
		timesSurvived++
		moneyEarned += 50000
		userRoll-- // Decrease the amount of bullets
	}

	// Calculate chance to die as a percent
	chanceToDie := (1.0 / float64(userRoll)) * 100.0

	// Win condition
	if moneyEarned % 250000 == 0 {
		timesWon++
		didUserWin = true
		winMessage = fmt.Sprintf(
			"You've won. Feel free to replay for more money or take what you've earned: %v",
			moneyEarned,
		)
		userRoll = 6 // Reset for next game
		attempt++
		timesSurvived = 0 // Reset survival counter
	}

	// Save values to session
	session.Values["userRoll"] = userRoll
	session.Values["moneyEarned"] = moneyEarned
	session.Values["timesWon"] = timesWon
	session.Values["timesSurvived"] = timesSurvived
	session.Values["attempt"] = attempt
	session.Values["didUserWin"] = didUserWin
	err = session.Save(c.Request, c.Writer)
    if err != nil {
        log.Println("Error saving session:", err)
        c.String(500, "Internal server error")
        return
    }

	c.HTML(http.StatusOK, "gametime.html", gin.H{
		"attempt": strconv.Itoa(attempt),
		"killShot": strconv.Itoa(killShot),
		"userRoll": strconv.Itoa(userRoll),
		"chanceToDie": fmt.Sprintf("%.2f%%", chanceToDie), // Format float to 2 decimals
		"timesWon":     strconv.Itoa(timesWon),
		"moneyEarned":  strconv.Itoa(moneyEarned),
		"winMessage":   winMessage,
		"didUserWin": didUserWin, // Pass this to the new template
		"gameStarted": gameStarted,
	})
}

func bannedHandler(c *gin.Context) {
	c.HTML(200, "banned.html", nil)
}

// Handler to start the game
func startGameHandler(c *gin.Context) {
	// Get session
	session, err := store.Get(c.Request, "game-session")
	if err != nil {
		log.Println("Error getting session:", err)
		c.String(500, "Internal server error")
		return
	}

	// Set the gameStarted flag to true to indicate that the game has started
	session.Values["gameStarted"] = true
	session.Values["userRoll"] = 6 // Reset roll to 6 at the start
	session.Values["moneyEarned"] = 0
	session.Values["timesWon"] = 0

	err = sessions.Save(c.Request, c.Writer)
	if err != nil {
		log.Println("Error saving session:", err)
		c.String(500, "Internal server error")
		return
	}

	// Redirect to /gametime to start the game
	c.Redirect(http.StatusPermanentRedirect, "/gametime")
}

func cashoutHandler(c *gin.Context) {
	session, err := store.Get(c.Request, "game-session")
	if err != nil {
		log.Printf("Error retrieving cookie value in cashoutHandler")
		c.String(500, "Internal server error")
	}
	delete(session.Values, "userRoll")
	delete(session.Values, "moneyEarned")
	delete(session.Values, "timesWon")
	delete(session.Values, "timesSurvived")
	delete(session.Values, "attempt")
	delete(session.Values, "didUserWin")
	delete(session.Values, "gameStarted")
	session.Save(c.Request, c.Writer)
	c.HTML(200, "cashout.html", gin.H{
		"moneyEarned": moneyEarned,
	})
}

func pregameStartHandler(c *gin.Context) {
	c.HTML(200, "pregamestart.html", nil)
}