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
	gin                *gin.Context
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

func (tnppt *TNPPT) ActivateHMACAuth() gin.HandlerFunc {
	return func(ginEngine *gin.Context) {
		tnppt.setTime()
		tnppt.gin = ginEngine.Copy()
		if err := tnppt.checkHMACPayload(); err != nil {
			message := errors.New(ErrFailedPayload.Error() + " - " + err.Error())
			tnppt.sendError(http.StatusBadRequest, message)
			return
		}
		if !tnppt.IsCredentialsValid(tnppt) {
			tnppt.sendError(http.StatusUnauthorized, ErrFailedAuthentication)
			return
		}
		if !tnppt.compareHash() {
			tnppt.sendError(http.StatusUnauthorized, ErrFailedAuthentication)
			return
		}
		if !tnppt.validateTTL() {
			tnppt.sendError(http.StatusUnauthorized, ErrFailedTTL)
			return
		}
		tnppt.next()
	}
}

func (tnppt *TNPPT) ActivateApiKeyAuth() gin.HandlerFunc {
	return func(ginEngine *gin.Context) {
		tnppt.setTime()
		tnppt.gin = ginEngine.Copy()
		if err := tnppt.checkAPIKeyPayload(); err != nil {
			message := errors.New(ErrFailedPayload.Error() + " - " + err.Error())
			tnppt.sendError(http.StatusBadRequest, message)
			return
		}
		if !tnppt.IsCredentialsValid(tnppt) {
			tnppt.sendError(http.StatusUnauthorized, ErrFailedAuthentication)
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

func (tnppt *TNPPT) checkHMACPayload() error {
	errBind := crunchyTools.HasError(tnppt.gin.BindHeader(&tnppt.PayloadHMAC), "TNPPT - INIT - Parsing Json", true)
	return errBind
}

func (tnppt *TNPPT) checkAPIKeyPayload() error {
	errBind := crunchyTools.HasError(tnppt.gin.BindHeader(&tnppt.PayloadAPIKey), "TNPPT - INIT - Parsing Json", true)
	return errBind
}

func (tnppt *TNPPT) LoginExists() {
	tnppt.IsLoginValid = true
}
func (tnppt *TNPPT) LoginDoestNotExists() {
	tnppt.IsLoginValid = false
}

func (tnppt *TNPPT) sendError(statusCode int, errorFetch error) {
	//TODO LOG SERVER SIDE ERRORS WITHIN LOGGER
	_ = tnppt.gin.AbortWithError(statusCode, errorFetch)
	tnppt.gin.JSON(statusCode, gin.H{
		"code":    statusCode,
		"message": errorFetch.Error(),
	})
}

func (tnppt *TNPPT) next() {
	tnppt.gin.Next()
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
