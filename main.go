package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"

	docs "swagger-project2/docs"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

var (
	secretkey  string = "secretkeyjwt"
	connection *gorm.DB
)

type User2 struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type User2SignUp struct {
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JsonResponse struct {
	Message string `json:"message"`
}

type Token struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	TokenString string `json:"token"`
}

func GetDatabase() *gorm.DB {
	databasename := "mydb"
	database := "postgres"
	databasepassword := "Nam12345"
	databaseurl := "postgres://postgres:" + databasepassword + "@localhost/" + databasename + "?sslmode=disable"

	connection, err := gorm.Open(database, databaseurl)
	if err != nil {
		log.Fatalln("Invalid database url")
	}
	sqldb := connection.DB()

	err = sqldb.Ping()
	if err != nil {
		log.Fatal("Database connected")
	}
	fmt.Println("Database connection successful.")
	return connection
}

func CloseDatabase(connection *gorm.DB) {
	sqldb := connection.DB()
	sqldb.Close()
}

func GeneratehashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateJWT(email, role string) (string, error) {
	var mySigningKey = []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		fmt.Errorf("Something went Wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}

func IsAuthorized() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Request.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				c.JSON(401, gin.H{
					"message": "No Token found",
				})
				c.Abort()
				return
			}
			c.JSON(400, gin.H{
				"message": "Something went wrong when get cookie",
			})
			c.Abort()
			return
		}
		tokenStr := cookie.Value

		var mySigningKey = []byte(secretkey)

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parsing token.")
			}
			return mySigningKey, nil
		})

		if err != nil {
			c.JSON(400, gin.H{
				"message": "Your Token has been expired",
			})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims["role"] == "admin" {
				c.Request.Header.Set("Role", "admin")
				return

			} else if claims["role"] == "user" {
				c.Request.Header.Set("Role", "user")
				return
			}
		}

		c.JSON(400, gin.H{
			"message": "Not Authorized",
		})
	}
}

// @BasePath /

//SignUp godoc
//@Summary Dang ky
//@Description Dang ky
//@Tags SignUp
//@Accept json
//@Produce json
//@Param  signup body User2SignUp true "Sign Up"
//@Success 200 {object} JsonResponse
//@Failure 400 {object} JsonResponse
//@Router /signup [post]
func SignUp(c *gin.Context) {
	var user User2
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(400, gin.H{
			"message": err.Error(),
		})
		return
	}

	var dbuser User2
	connection.Where("email = ?", user.Email).First(&dbuser)

	if dbuser.Email != "" {
		c.JSON(400, gin.H{
			"message": "Email already in use",
		})
		return
	}

	user.Password, err = GeneratehashPassword(user.Password)
	if err != nil {
		c.JSON(400, gin.H{
			"message": "Error in hashing password",
		})
		return
	}

	connection.Create(&user)
	c.JSON(200, gin.H{
		"message": "Sign Up successfully!!",
	})
}

//SignIn godoc
//@Summary Dang nhap
//@Description Dang nhap
//@Tags SignIn
//@Accept json
//@Produce json
//@Param  signin body Authentication true "Sign In"
//@Success 200 {object} JsonResponse
//@Failure 400 {object} JsonResponse
//@Router /signin [post]
func SignIn(c *gin.Context) {
	var authDetails Authentication
	err := c.ShouldBindJSON(&authDetails)
	if err != nil {
		c.JSON(400, gin.H{
			"message": "Error in reading payload",
		})
		return
	}

	var authUser User2
	connection.Where("email = ?", authDetails.Email).First(&authUser)
	if authUser.Email == "" {
		c.JSON(400, gin.H{
			"message": "Email is incorrect",
		})
	} else {
		check := CheckPasswordHash(authDetails.Password, authUser.Password)
		if !check {
			c.JSON(400, gin.H{
				"message": "Password is incorrect",
			})
			return
		}

		validToken, err := GenerateJWT(authUser.Email, authUser.Role)
		if err != nil {
			c.JSON(400, gin.H{
				"message": "Failed to generate token",
			})
			return
		}

		var token Token
		token.Email = authUser.Email
		token.Role = authUser.Role
		token.TokenString = validToken

		http.SetCookie(c.Writer, &http.Cookie{
			Name:  "token",
			Value: validToken,
		})

		c.JSON(200, gin.H{
			"message": "Sign in successfully!!",
			"email":   token.Email,
			"role":    token.Role,
			"token":   token.TokenString,
		})
	}
}

//AdminIndex godoc
//@Summary Lay trang chu Admin
//@Description Lay trang chu Admin
//@Tags AdminIndex
//@Accept json
//@Produce json
//@Success 200 {object} JsonResponse
//@Failure 400 {object} JsonResponse
//@Failure 401 {object} JsonResponse
//@Router /admin [get]
func AdminIndex(c *gin.Context) {
	if c.Request.Header.Get("Role") != "admin" {
		c.JSON(401, gin.H{
			"message": "Not authorized",
		})
		return
	}
	c.JSON(200, gin.H{
		"message": "Welcome, Admin",
	})
}

//UserIndex godoc
//@Summary Lay trang chu User
//@Description Lay trang chu User
//@Tags UserIndex
//@Accept json
//@Produce json
//@Success 200 {object} JsonResponse
//@Failure 400 {object} JsonResponse
//@Failure 401 {object} JsonResponse
//@Router /user [get]
func UserIndex(c *gin.Context) {
	if c.Request.Header.Get("Role") != "user" {
		c.JSON(401, gin.H{
			"message": "Not authorized",
		})
		return
	}
	c.JSON(200, gin.H{
		"message": "Welcome, User",
	})
}

//SignOut godoc
//@Summary Dang xuat
//@Description Dang xuat
//@Tags SignOut
//@Accept json
//@Produce json
//@Success 200 {object} JsonResponse
//@Router /user/signout [post]
//@Router /admin/signout [post]
func SignOut(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:  "token",
		Value: "",
		Path:  "/",
	})
	c.JSON(200, gin.H{
		"message": "Signed Out",
	})
}

//DeleteUser godoc
//@Summary  Xoa User
//@Description Xoa User
//@Tags DeleteUser
//@Accept json
//@Produce json
//@Param  id path int true "User ID"
//@Success 200 {object} JsonResponse
//@Failure 400 {object} JsonResponse
//@Failure 401 {object} JsonResponse
//@Router /admin/delete/{id} [post]
func DeleteUser(c *gin.Context) {
	if c.Request.Header.Get("Role") != "admin" {
		c.JSON(401, gin.H{
			"message": "Not authorized",
		})
		return
	}

	userId := c.Param("id")

	var dbuser User2

	result := connection.Where("id = ?", userId).First(&dbuser)
	if result.Error != nil {
		c.JSON(400, gin.H{
			"message": "This User does not exist",
		})
		return
	}

	if dbuser.Role == "admin" {
		c.JSON(400, gin.H{
			"message": "Cannot delete Admin",
		})
	} else {
		connection.Unscoped().Delete(&dbuser)
		c.JSON(200, gin.H{
			"message": "Delete User " + userId + " successfully!!",
		})
	}
}

func main() {
	connection = GetDatabase()
	defer CloseDatabase(connection)

	docs.SwaggerInfo.BasePath = "/"

	router := gin.Default()

	router.POST("/signin", SignIn)
	router.POST("/signup", SignUp)
	router.POST("/admin/signout", IsAuthorized(), SignOut)
	router.POST("/admin/delete/:id", IsAuthorized(), DeleteUser)
	router.GET("/admin", IsAuthorized(), AdminIndex)
	router.POST("/user/signout", IsAuthorized(), SignOut)
	router.GET("/user", IsAuthorized(), UserIndex)

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	router.Run(":3000")
}
