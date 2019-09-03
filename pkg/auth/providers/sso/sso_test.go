package sso

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DUserConvert(t *testing.T) {
	origin := DUserV2{
		DCommon: DCommon{
			UserID: "test1",
		},
		IamOpenID: "abc",
	}
	target := origin.ToDUser()
	expect := DUser{
		DCommon: DCommon{
			UserID: "test1",
		},
		IamOpenID: "abc",
	}
	assert.Equal(t, expect, target, "duser convertion fails")
}
