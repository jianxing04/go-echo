package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3" // 1. Import the YAML package
)

// Config struct to hold all your configuration
type Config struct {
	Database struct {
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
	} `yaml:"database"`
	Server struct {
		Address string `yaml:"address"`
	} `yaml:"server"`
	Session struct {
		Secret string `yaml:"secret"`
	} `yaml:"session"`
}

// User and Message models remain the same
type User struct {
	ID        int
	Username  string
	Password  string
	CreatedAt time.Time
}

type Message struct {
	ID              int
	UserID          int
	OriginalMessage string
	ReversedMessage string
	CreatedAt       time.Time
}

type PageData struct {
	Title    string
	User     *User
	Messages []Message
	Error    string
	Success  string
}

var db *sql.DB
var cfg *Config // Global variable to hold the loaded config

// loadConfig reads configuration from file.
func loadConfig(path string) (*Config, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(f, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func main() {
	// 2. Load configuration from the YAML file at startup
	var err error
	cfg, err = loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Initialize database connection
	initDB()
	defer db.Close()

	// Create Gin router
	router := gin.Default()

	// 3. Use the session secret from the loaded config
	store := cookie.NewStore([]byte(cfg.Session.Secret))
	router.Use(sessions.Sessions("echo_session", store))

	// Load templates and static files (no changes here)
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")

	// Route configuration (no changes here)
	router.GET("/", homeHandler)
	router.GET("/register", registerFormHandler)
	router.POST("/register", registerHandler)
	router.GET("/login", loginFormHandler)
	router.POST("/login", loginHandler)
	router.GET("/logout", logoutHandler)
	router.POST("/echo", echoHandler)
	router.DELETE("/message/:id", deleteMessageHandler)

	// 4. Use the server address from the loaded config
	fmt.Printf("Starting server on %s...\n", cfg.Server.Address)
	router.Run(cfg.Server.Address)
}

func initDB() {
	// 5. Build the DSN from the loaded config
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
	)

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error pinging database: %v", err)
	}

	fmt.Println("Successfully connected to MySQL database")
}

// 反转字符串函数
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// 处理器函数
func homeHandler(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")

	if userID == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// 获取当前用户
	var user User
	err := db.QueryRow("SELECT id, username, created_at FROM users WHERE id = ?", userID).Scan(
		&user.ID, &user.Username, &user.CreatedAt,
	)
	if err != nil {
		session.AddFlash("User not found", "error")
		session.Save()
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// 获取用户消息历史
	rows, err := db.Query("SELECT id, original_message, reversed_message, created_at FROM messages WHERE user_id = ? ORDER BY created_at DESC", userID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "index.html", PageData{
			Title: "Home",
			User:  &user,
			Error: "Failed to load messages",
		})
		return
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		err := rows.Scan(&msg.ID, &msg.OriginalMessage, &msg.ReversedMessage, &msg.CreatedAt)
		if err == nil {
			messages = append(messages, msg)
		}
	}

	c.HTML(http.StatusOK, "index.html", PageData{
		Title:    "Echo Service",
		User:     &user,
		Messages: messages,
	})
}

func registerFormHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", PageData{Title: "Register"})
}

func registerHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	password2 := c.PostForm("password2") // 1. Get the confirmation password

	// 2. Check if passwords are required (same as before)
	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "register.html", PageData{
			Title: "Register",
			Error: "Username and password are required",
		})
		return
	}

	// 3. NEW: Check if passwords match
	if password != password2 {
		c.HTML(http.StatusBadRequest, "register.html", PageData{
			Title: "Register",
			Error: "Passwords do not match", // Send a specific error
		})
		return
	}

	// 4. The rest of the logic remains the same
	// Check if username already exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil || count > 0 {
		c.HTML(http.StatusBadRequest, "register.html", PageData{
			Title: "Register",
			Error: "Username already exists",
		})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", PageData{
			Title: "Register",
			Error: "Failed to create user",
		})
		return
	}

	// Create user
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hashedPassword))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", PageData{
			Title: "Register",
			Error: "Failed to create user",
		})
		return
	}

	c.HTML(http.StatusOK, "login.html", PageData{
		Title:   "Login",
		Success: "Registration successful! Please login.",
	})
}

func loginFormHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", PageData{Title: "Login"})
}

func loginHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.html", PageData{
			Title: "Login",
			Error: "Username and password are required",
		})
		return
	}

	// 获取用户
	var user User
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(
		&user.ID, &user.Username, &user.Password,
	)

	if err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", PageData{
			Title: "Login",
			Error: "Invalid username or password",
		})
		return
	}

	// 验证密码
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", PageData{
			Title: "Login",
			Error: "Invalid username or password",
		})
		return
	}

	// 设置会话
	session := sessions.Default(c)
	session.Set("user_id", user.ID)
	session.Save()

	c.Redirect(http.StatusFound, "/")
}

func logoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func echoHandler(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")

	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	message := strings.TrimSpace(c.PostForm("message"))
	if message == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Message cannot be empty"})
		return
	}

	reversed := reverseString(message)

	// MODIFIED: Capture the result of the database execution
	result, err := db.Exec("INSERT INTO messages (user_id, original_message, reversed_message) VALUES (?, ?, ?)",
		userID, message, reversed)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save message"})
		return
	}

	// NEW: Get the ID of the row we just inserted
	newMessageID, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve message ID"})
		return
	}

	// MODIFIED: Add the new message ID to the JSON response
	c.JSON(http.StatusOK, gin.H{
		"id":        newMessageID, // The new message ID
		"original":  message,
		"reversed":  reversed,
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
	})
}

// NEW: deleteMessageHandler handles deleting a specific message
func deleteMessageHandler(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")

	// 1. Ensure the user is logged in
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// 2. Get the message ID from the URL parameter
	messageID := c.Param("id")
	if messageID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Message ID is required"})
		return
	}

	// 3. Execute the delete query
	// IMPORTANT: We include "user_id = ?" in the WHERE clause.
	// This is a critical security check to ensure users can only delete their own messages.
	result, err := db.Exec("DELETE FROM messages WHERE id = ? AND user_id = ?", messageID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete message"})
		return
	}

	// 4. Check if a row was actually deleted
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify deletion"})
		return
	}

	if rowsAffected == 0 {
		// This means the message didn't exist or didn't belong to the user
		c.JSON(http.StatusNotFound, gin.H{"error": "Message not found or you do not have permission to delete it"})
		return
	}

	// 5. Send a success response
	c.JSON(http.StatusOK, gin.H{"success": true})
}