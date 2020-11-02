package tnpptMiddleware

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	crunchyTools "github.com/crunchy-apps/crunchy-tools"
	"github.com/gin-gonic/gin"
)

type PayloadHMACFormat struct {
	Hash  string `header:"HMAC_HASH" binding:"required"`
	Time  int64  `header:"HMAC_TIME" binding:"required"`
	Login string `header:"HMAC_LOGIN" binding:"required"`
}

type PayloadAPIKeyFormat struct {
	APIKey string `header:"API_KEY" binding:"required"`
}

type UserInfo struct {
	ID       interface{}
	Login    string
	Password string
}

type Security struct {
	TTL          int64
	TimeReceived int64
}

type TNPPT struct {
	PayloadHMAC        PayloadHMACFormat
	PayloadAPIKey      PayloadAPIKeyFormat
	Security           Security
	UserInfo           UserInfo
	IsLoginValid       bool
	Gin                *gin.Context
	IsCredentialsValid func(tnppt *TNPPT) bool
}

var (
	ErrFailedAuthentication = errors.New("incorrect Username or Password")
	ErrFailedPayload        = errors.New("incorrect Headers")
	ErrFailedTTL            = errors.New("TTL obsolete")
)

func New(tnppt *TNPPT) (*TNPPT, error) {
	return tnppt.Init()
}

func NewFake(tnppt *TNPPT) (*TNPPT, error) {
	return tnppt.InitFake()
}

func (tnppt *TNPPT) ActivateHMACAuthFake(id interface{}) gin.HandlerFunc {
	return func(ginEngine *gin.Context) {
		tnppt.setTime()
		tnppt.Gin = ginEngine.Copy()
		tnppt.UserInfo.ID = id
		tnppt.next()
	}
}

func (tnppt *TNPPT) ActivateHMACAuth() gin.HandlerFunc {
	return func(ginEngine *gin.Context) {
		tnppt.setTime()
		tnppt.Gin = ginEngine.Copy()
		if err := tnppt.checkHMACPayload(); err != nil {
			message := errors.New(ErrFailedPayload.Error() + " - " + err.Error())
			tnppt.sendError(ginEngine, http.StatusUnauthorized, message)
			return
		}
		if !tnppt.IsCredentialsValid(tnppt) {
			fmt.Println("user not found")
			tnppt.sendError(ginEngine, http.StatusUnauthorized, ErrFailedAuthentication)
			return
		}
		if !tnppt.compareHash() {
			fmt.Println("incorrect hash")
			tnppt.sendError(ginEngine, http.StatusUnauthorized, ErrFailedAuthentication)
			return
		}
		if !tnppt.validateTTL() {
			tnppt.sendError(ginEngine, http.StatusUnauthorized, ErrFailedTTL)
			return
		}
		tnppt.next()
	}
}

func (tnppt *TNPPT) ActivateApiKeyAuth() gin.HandlerFunc {
	return func(ginEngine *gin.Context) {
		tnppt.setTime()
		tnppt.Gin = ginEngine.Copy()
		if err := tnppt.checkAPIKeyPayload(); err != nil {
			message := errors.New(ErrFailedPayload.Error() + " - " + err.Error())
			tnppt.sendError(ginEngine, http.StatusUnauthorized, message)
			return
		}
		if !tnppt.IsCredentialsValid(tnppt) {
			tnppt.sendError(ginEngine, http.StatusUnauthorized, ErrFailedAuthentication)
			return
		}
		tnppt.next()
	}
}

func (tnppt *TNPPT) Init() (*TNPPT, error) {
	tnppt.IsLoginValid = false
	if tnppt.IsCredentialsValid == nil {
		return nil, errors.New("TNPPT - You need to set the FetchUsersInfos")
	}
	if tnppt.Security.TTL == 0 {
		tnppt.Security.TTL = 800
	}
	return tnppt, nil
}

func (tnppt *TNPPT) InitFake() (*TNPPT, error) {
	tnppt.IsLoginValid = true
	return tnppt, nil
}

func (tnppt *TNPPT) checkHMACPayload() error {
	if tnppt.Gin.GetHeader("HMAC_LOGIN") != "" &&
		tnppt.Gin.GetHeader("HMAC_HASH") != "" &&
		tnppt.Gin.GetHeader("HMAC_TIME") != "" {
		_, errTime := strconv.Atoi(tnppt.Gin.GetHeader("HMAC_TIME"))
		if errTime != nil {
			return fmt.Errorf("[HMAC] Incorrect Payload")
		}
		errBind := crunchyTools.HasError(tnppt.Gin.BindHeader(&tnppt.PayloadHMAC), "TNPPT - INIT - Parsing Json", true)
		return errBind
	}
	return fmt.Errorf("[HMAC] No payload detected")
}

func (tnppt *TNPPT) checkAPIKeyPayload() error {
	if tnppt.Gin.GetHeader("API_KEY") != "" {
		errBind := crunchyTools.HasError(tnppt.Gin.BindHeader(&tnppt.PayloadAPIKey), "TNPPT - INIT - Parsing Json", true)
		return errBind
	}
	return fmt.Errorf("[HMAC] No payload detected")

}

func (tnppt *TNPPT) LoginExists() {
	tnppt.IsLoginValid = true
}
func (tnppt *TNPPT) LoginDoestNotExists() {
	tnppt.IsLoginValid = false
}

func (tnppt *TNPPT) sendError(ginEngine *gin.Context, statusCode int, errorFetch error) {
	//TODO LOG SERVER SIDE ERRORS WITHIN LOGGER
	_ = ginEngine.AbortWithError(statusCode, errorFetch)
	ginEngine.JSON(statusCode, gin.H{
		"code":    statusCode,
		"message": errorFetch.Error(),
	})
}

func (tnppt *TNPPT) next() {
	tnppt.Gin.Next()
}

func (tnppt *TNPPT) GetTimeMilliseconds() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func (tnppt *TNPPT) setTime() {
	tnppt.Security.TimeReceived = tnppt.GetTimeMilliseconds()
}

func (tnppt *TNPPT) validateTTL() bool {
	if tnppt.Security.TimeReceived-tnppt.PayloadHMAC.Time <= tnppt.Security.TTL {
		return true
	}
	return false
}

func (tnppt *TNPPT) createHash() string {
	hasher := sha256.New()
	hashPayload := tnppt.UserInfo.Login + tnppt.UserInfo.Password + strconv.FormatInt(tnppt.PayloadHMAC.Time, 10)
	hasher.Write([]byte(hashPayload))
	hash := hasher.Sum(nil)
	return fmt.Sprintf("%x", hash)
}

func (tnppt *TNPPT) compareHash() bool {
	generatedHash := tnppt.createHash()
	if isSame := strings.Compare(generatedHash, tnppt.PayloadHMAC.Hash); isSame == 0 {
		return true
	}
	return false
}
