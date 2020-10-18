package tnpptMiddleware

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func ginMockHandler(auth *TNPPT) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/login", auth.ActivateHMACAuth())

	return router
}
func TestNew(t *testing.T) {
	type args struct {
		tnppt *TNPPT
	}
	tests := []struct {
		name    string
		args    args
		want    *TNPPT
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	fmt.Println("ok")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.tnppt)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTNPPT_createHash(t *testing.T) {
	type fields struct {
		Payload        PayloadHMACFormat
		UserInfo       UserInfo
		IsLoginValid   bool
		gin            *gin.Context
		FetchUserInfos func(tnppt *TNPPT) bool
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "Hash",
			fields: fields{
				Payload: PayloadHMACFormat{
					Hash:  "12345",
					Time:  123456743,
					Login: "steven",
				},
				UserInfo:     UserInfo{},
				IsLoginValid: false,
				gin:          nil,
				FetchUserInfos: func(tnppt *TNPPT) bool {
					user := UserInfo{
						Login:    "steven",
						Password: "pass",
					}
					tnppt.UserInfo = user
					return true
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tnppt, err := New(&TNPPT{
				PayloadHMAC:        tt.fields.Payload,
				UserInfo:           tt.fields.UserInfo,
				IsLoginValid:       tt.fields.IsLoginValid,
				Gin:                tt.fields.gin,
				IsCredentialsValid: tt.fields.FetchUserInfos,
			})
			if err != nil {
				t.Fatal(err)
			}
			tnppt.IsCredentialsValid(tnppt)
			tnppt.createHash()
		})
	}
}

func TestTNPPT_compareHash(t *testing.T) {
	type fields struct {
		Payload        PayloadHMACFormat
		UserInfo       UserInfo
		IsLoginValid   bool
		gin            *gin.Context
		FetchUserInfos func(tnppt *TNPPT) bool
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "Hash-not-valid",
			fields: fields{
				Payload: PayloadHMACFormat{
					Hash:  "verybadhashfromspace",
					Time:  123456743,
					Login: "steven",
				},
				UserInfo:     UserInfo{},
				IsLoginValid: false,
				gin:          nil,
				FetchUserInfos: func(tnppt *TNPPT) bool {
					user := UserInfo{
						Login:    "steven",
						Password: "pass",
					}
					tnppt.UserInfo = user
					return true
				},
			},
			want: false,
		},
		{
			name: "Hash-valid",
			fields: fields{
				Payload: PayloadHMACFormat{
					Hash:  "dd463af299746906df9bd1c0ec1dc988ae2faa52be1200be10fb246766f04ba0",
					Time:  123456743,
					Login: "steven",
				},
				UserInfo:     UserInfo{},
				IsLoginValid: false,
				gin:          nil,
				FetchUserInfos: func(tnppt *TNPPT) bool {
					user := UserInfo{
						Login:    "steven",
						Password: "pass",
					}
					tnppt.UserInfo = user
					return true
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tnppt, err := New(&TNPPT{
				PayloadHMAC:        tt.fields.Payload,
				UserInfo:           tt.fields.UserInfo,
				IsLoginValid:       tt.fields.IsLoginValid,
				Gin:                tt.fields.gin,
				IsCredentialsValid: tt.fields.FetchUserInfos,
			})
			if err != nil {
				t.Fatal(err)
			}
			tnppt.IsCredentialsValid(tnppt)
			if tnppt.compareHash() != tt.want {
				t.Fail()
			}
		})
	}
}

func TestTNPPT_getTime(t *testing.T) {
	type fields struct {
		Payload        PayloadHMACFormat
		UserInfo       UserInfo
		IsLoginValid   bool
		gin            *gin.Context
		FetchUserInfos func(tnppt *TNPPT) bool
	}
	tnppt, err := New(&TNPPT{
		PayloadHMAC:  PayloadHMACFormat{},
		UserInfo:     UserInfo{},
		IsLoginValid: false,
		Gin:          nil,
		IsCredentialsValid: func(tnppt *TNPPT) bool {
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tnppt.setTime()
	if tnppt.Security.TimeReceived == 0 {
		t.Fail()
	}
}

func TestTNPPT_validateTTL(t *testing.T) {
	type fields struct {
		Payload        PayloadHMACFormat
		Security       Security
		UserInfo       UserInfo
		IsLoginValid   bool
		gin            *gin.Context
		FetchUserInfos func(tnppt *TNPPT) bool
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "TTL-crossed",
			fields: fields{
				Payload: PayloadHMACFormat{
					Hash:  "7bb382b6324b570e5ce882dfa87f4684e68a41b6a9e2ca83a7bbab588ec2dab9",
					Time:  1600344748887,
					Login: "steven",
				},
				Security: Security{
					TTL:          800,
					TimeReceived: 1600344749688,
				},
				UserInfo:     UserInfo{},
				IsLoginValid: false,
				gin:          nil,
				FetchUserInfos: func(tnppt *TNPPT) bool {
					user := UserInfo{
						Login:    "steven",
						Password: "pass",
					}
					tnppt.UserInfo = user
					return true
				},
			},
			want: false,
		},
		{
			name: "TTL-valid",
			fields: fields{
				Payload: PayloadHMACFormat{
					Hash:  "7bb382b6324b570e5ce882dfa87f4684e68a41b6a9e2ca83a7bbab588ec2dab9",
					Time:  1600344748887,
					Login: "steven",
				},
				Security: Security{
					TTL:          800,
					TimeReceived: 1600344749687,
				},
				UserInfo:     UserInfo{},
				IsLoginValid: false,
				gin:          nil,
				FetchUserInfos: func(tnppt *TNPPT) bool {
					user := UserInfo{
						Login:    "steven",
						Password: "pass",
					}
					tnppt.UserInfo = user
					return true
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tnppt, err := New(&TNPPT{
				PayloadHMAC:        tt.fields.Payload,
				Security:           tt.fields.Security,
				UserInfo:           tt.fields.UserInfo,
				IsLoginValid:       tt.fields.IsLoginValid,
				Gin:                tt.fields.gin,
				IsCredentialsValid: tt.fields.FetchUserInfos,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := tnppt.validateTTL(); got != tt.want {
				t.Errorf("validateTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTNPPT_HmacCompareProcess(t *testing.T) {
	type fields struct {
		Payload        PayloadHMACFormat
		Security       Security
		UserInfo       UserInfo
		IsLoginValid   bool
		gin            *gin.Context
		FetchUserInfos func(tnppt *TNPPT) bool
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "HMAC_all-clear",
			fields: fields{
				Payload: PayloadHMACFormat{
					Hash:  "7bb382b6324b570e5ce882dfa87f4684e68a41b6a9e2ca83a7bbab588ec2dab9",
					Login: "steven",
				},
				Security: Security{
					TTL: 800,
				},
				UserInfo:     UserInfo{},
				IsLoginValid: false,
				gin:          nil,
				FetchUserInfos: func(tnppt *TNPPT) bool {
					user := UserInfo{
						Login:    "steven",
						Password: "pass",
					}
					tnppt.UserInfo = user
					return true
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tnppt, err := New(&TNPPT{
				PayloadHMAC:        tt.fields.Payload,
				Security:           tt.fields.Security,
				UserInfo:           tt.fields.UserInfo,
				IsCredentialsValid: tt.fields.FetchUserInfos,
			})
			if err != nil {
				t.Fatal(err)
			}

			timeNow := tnppt.GetTimeMilliseconds()
			tnppt.IsCredentialsValid(tnppt)
			hashPayload := tnppt.UserInfo.Login + tnppt.UserInfo.Password + strconv.FormatInt(timeNow, 10)
			hash := sha256.New()
			hash.Write([]byte(hashPayload))
			finalHash := fmt.Sprintf("%x", hash.Sum(nil))
			ginMock := ginMockHandler(tnppt)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/login", nil)
			req.Header.Add("HMAC_HASH", finalHash)
			req.Header.Add("HMAC_LOGIN", tnppt.UserInfo.Login)
			req.Header.Add("HMAC_TIME", strconv.FormatInt(timeNow, 10))

			ginMock.ServeHTTP(w, req)

			assert.Equal(t, 200, w.Code)
			assert.Equal(t, "", w.Body.String())
		})
	}
	//auth :=
}
