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

type PayloadFormat struct {
	Hash  string `json:"TNPPT_HASH" binding:"required"`
	Time  int64  `json:"TNPPT_TIME" binding:"required"`
	TTL   string `json:"TNPPT_TTL" binding:"required"`
	Login string `json:"TNPPT_LOGIN" binding:"required"`
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
	Payload        PayloadFormat
	Security       Security
	UserInfo       UserInfo
	IsLoginValid   bool
	gin            *gin.Context
	FetchUserInfos func(tnppt *TNPPT) bool
}

var (
	ErrFailedAuthentication = errors.New("incorrect Username or Password")
	ErrFailedTTL            = errors.New("TTL obsolete")
)

func New(tnppt *TNPPT) (*TNPPT, error) {
	return tnppt.Init()
}

func (tnppt *TNPPT) Activate() gin.HandlerFunc {
	return func(ginEngine *gin.Context) {
		tnppt.setTime()
		tnppt.gin = ginEngine
		if err := tnppt.checkPayload(); err != nil {
			tnppt.sendError(http.StatusBadRequest, err)
			return
		}
		if !tnppt.FetchUserInfos(tnppt) {
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

func (tnppt *TNPPT) Init() (*TNPPT, error) {
	tnppt.IsLoginValid = false
	if tnppt.FetchUserInfos == nil {
		return nil, errors.New("TNPPT - You need to set the FetchUsersInfos")
	}
	if tnppt.Security.TTL == 0 {
		tnppt.Security.TTL = 800
	}
	return tnppt, nil
}

func (tnppt *TNPPT) checkPayload() error {
	errBind := crunchyTools.HasError(tnppt.gin.BindJSON(&tnppt.Payload), "TNPPT - INIT - Parsing Json", true)
	return errBind
}

func (tnppt *TNPPT) LoginExists() {
	tnppt.IsLoginValid = true
}
func (tnppt *TNPPT) LoginDoestNotExists() {
	tnppt.IsLoginValid = false
}

func (tnppt *TNPPT) sendError(statusCode int, errorFetch error) {
	_ = tnppt.gin.AbortWithError(statusCode, errorFetch)
	tnppt.gin.JSON(http.StatusUnauthorized, gin.H{
		"code":    statusCode,
		"message": errorFetch.Error(),
	})
}

func (tnppt *TNPPT) next() {
	tnppt.gin.Next()
}

func (tnppt *TNPPT) setTime() {
	tnppt.Security.TimeReceived = time.Now().UnixNano() / int64(time.Millisecond)
}

func (tnppt *TNPPT) validateTTL() bool {
	if tnppt.Security.TimeReceived-tnppt.Payload.Time <= tnppt.Security.TTL {
		return true
	}
	return false
}

func (tnppt *TNPPT) createHash() string {
	hasher := sha256.New()
	hashPayload := tnppt.UserInfo.Login + tnppt.UserInfo.Password + strconv.FormatInt(tnppt.Payload.Time, 10)
	hasher.Write([]byte(hashPayload))
	hash := hasher.Sum(nil)
	return fmt.Sprintf("%x", hash)
}

func (tnppt *TNPPT) compareHash() bool {
	generatedHash := tnppt.createHash()
	if isSame := strings.Compare(generatedHash, tnppt.Payload.Hash); isSame == 0 {
		return true
	}
	return false
}
