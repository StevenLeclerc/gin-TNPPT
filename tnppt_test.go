package tnpptMiddleware

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
)

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
		Payload        PayloadFormat
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
				Payload: PayloadFormat{
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
				Payload:        tt.fields.Payload,
				UserInfo:       tt.fields.UserInfo,
				IsLoginValid:   tt.fields.IsLoginValid,
				gin:            tt.fields.gin,
				FetchUserInfos: tt.fields.FetchUserInfos,
			})
			if err != nil {
				t.Fatal(err)
			}
			tnppt.FetchUserInfos(tnppt)
			tnppt.createHash()
		})
	}
}

func TestTNPPT_compareHash(t *testing.T) {
	type fields struct {
		Payload        PayloadFormat
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
				Payload: PayloadFormat{
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
				Payload: PayloadFormat{
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
				Payload:        tt.fields.Payload,
				UserInfo:       tt.fields.UserInfo,
				IsLoginValid:   tt.fields.IsLoginValid,
				gin:            tt.fields.gin,
				FetchUserInfos: tt.fields.FetchUserInfos,
			})
			if err != nil {
				t.Fatal(err)
			}
			tnppt.FetchUserInfos(tnppt)
			if tnppt.compareHash() != tt.want {
				t.Fail()
			}
		})
	}
}

func TestTNPPT_getTime(t *testing.T) {
	type fields struct {
		Payload        PayloadFormat
		UserInfo       UserInfo
		IsLoginValid   bool
		gin            *gin.Context
		FetchUserInfos func(tnppt *TNPPT) bool
	}
	tnppt, err := New(&TNPPT{
		Payload:      PayloadFormat{},
		UserInfo:     UserInfo{},
		IsLoginValid: false,
		gin:          nil,
		FetchUserInfos: func(tnppt *TNPPT) bool {
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
		Payload        PayloadFormat
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
				Payload: PayloadFormat{
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
				Payload: PayloadFormat{
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
				Payload:        tt.fields.Payload,
				Security:       tt.fields.Security,
				UserInfo:       tt.fields.UserInfo,
				IsLoginValid:   tt.fields.IsLoginValid,
				gin:            tt.fields.gin,
				FetchUserInfos: tt.fields.FetchUserInfos,
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
