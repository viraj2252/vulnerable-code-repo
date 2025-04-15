package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"gopkg.in/yaml.v2"
)

// VULNERABILITY: Hardcoded credentials
const (
	dbUser     = "root"
	dbPassword = "password123"
	dbHost     = "localhost:3306"
	dbName     = "vulnerable_db"
)

// VULNERABILITY: Insecure session store
var (
	// VULNERABILITY: Hardcoded secret key
	sessionStore = sessions.NewCookieStore([]byte("super-secret-key-value-that-is-hardcoded"))
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"` // VULNERABILITY: Password stored in struct
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
}

type Config struct {
	Debug    bool   `yaml:"debug"`
	LogLevel string `yaml:"log_level"`
	Secret   string `yaml:"secret"`
}

func main() {
	// VULNERABILITY: Debug mode enabled
	gin.SetMode(gin.DebugMode)

	router := gin.Default()
	
	// Connect to database
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbHost, dbName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// API routes
	router.POST("/login", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// VULNERABILITY: SQL Injection
		query := fmt.Sprintf("SELECT id, username, email, is_admin FROM users WHERE username='%s' AND password='%s'", 
			user.Username, user.Password)
		
		row := db.QueryRow(query)
		
		var result User
		err := row.Scan(&result.ID, &result.Username, &result.Email, &result.IsAdmin)
		if err != nil {
			// VULNERABILITY: Information disclosure in error
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Login failed: " + err.Error()})
			return
		}

		// Create session
		session, _ := sessionStore.Get(c.Request, "session")
		session.Values["user_id"] = result.ID
		session.Values["username"] = result.Username
		session.Values["is_admin"] = result.IsAdmin
		session.Save(c.Request, c.ResponseWriter)

		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
			"user":    result,
		})
	})

	// VULNERABILITY: Path Traversal
	router.GET("/download", func(c *gin.Context) {
		filename := c.Query("filename")
		if filename == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Filename parameter is required"})
			return
		}

		// VULNERABILITY: Direct path manipulation
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Header("Content-Disposition", "attachment; filename="+filepath.Base(filename))
		c.Data(http.StatusOK, "application/octet-stream", data)
	})

	// VULNERABILITY: Command Injection
	router.GET("/ping", func(c *gin.Context) {
		host := c.Query("host")
		if host == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Host parameter is required"})
			return
		}

		// VULNERABILITY: Unsanitized input to command
		cmd := exec.Command("ping", "-c", "4", host)
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.String(http.StatusOK, string(output))
	})

	// VULNERABILITY: XSS
	router.GET("/search", func(c *gin.Context) {
		query := c.Query("q")
		
		// Perform a search (simulated)
		results := fmt.Sprintf(`
			<h1>Search Results for: %s</h1>
			<p>No results found.</p>
		`, query) // VULNERABILITY: Unsanitized input in HTML

		// VULNERABILITY: Content-Type allows XSS
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, results)
	})

	// VULNERABILITY: CSRF
	router.POST("/update-profile", func(c *gin.Context) {
		// VULNERABILITY: No CSRF token validation
		session, _ := sessionStore.Get(c.Request, "session")
		userID, ok := session.Values["user_id"].(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		var userData struct {
			Email string `json:"email"`
		}
		if err := c.ShouldBindJSON(&userData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Update user in database
		stmt, err := db.Prepare("UPDATE users SET email = ? WHERE id = ?")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer stmt.Close()

		_, err = stmt.Exec(userData.Email, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Profile updated"})
	})

	// VULNERABILITY: Insecure YAML Parsing
	router.POST("/config", func(c *gin.Context) {
		configData, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}

		var config Config
		// VULNERABILITY: Unsafe YAML parsing
		err = yaml.Unmarshal(configData, &config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse YAML: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"config": config})
	})

	// VULNERABILITY: Open redirect
	router.GET("/redirect", func(c *gin.Context) {
		url := c.Query("url")
		if url == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "URL parameter is required"})
			return
		}

		// VULNERABILITY: No validation of redirect URL
		c.Redirect(http.StatusFound, url)
	})

	// VULNERABILITY: Directory traversal in file listing
	router.GET("/files", func(c *gin.Context) {
		dir := c.Query("dir")
		if dir == "" {
			dir = "."
		}

		// VULNERABILITY: Unsanitized directory path
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read directory: " + err.Error()})
			return
		}

		var fileList []string
		for _, file := range files {
			fileList = append(fileList, file.Name())
		}

		c.JSON(http.StatusOK, gin.H{"files": fileList})
	})

	// VULNERABILITY: Insecure file upload
	router.POST("/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
			return
		}

		// VULNERABILITY: No validation of file type or content
		filename := filepath.Join("uploads", file.Filename)
		
		// Ensure uploads directory exists
		if _, err := os.Stat("uploads"); os.IsNotExist(err) {
			os.Mkdir("uploads", 0755)
		}

		if err := c.SaveUploadedFile(file, filename); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":  "File uploaded successfully",
			"filename": file.Filename,
		})
	})

	// VULNERABILITY: No rate limiting, exposed on all interfaces
	router.Run(":8080")
} 