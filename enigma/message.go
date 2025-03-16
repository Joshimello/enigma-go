package enigma

func GetCodeMessage(code uint8) string {
	errMap := map[uint8]string{
		0x00: "STATUS_OK",
		0x01: "ERR_MX_NO_EXIST",
		0x02: "ERR_MX_HANDLE_FAIL",
		0x10: "ERR_MX_UPDATE_KEY_FAIL",
		0x31: "ERR_SEND_LOGIN_CMD_FAIL",
		0x32: "ERR_INVALID_PWD_LENGTH",
		0x33: "ERR_LOGIN_FAIL",
		0x35: "ERR_OVER_FAIL_RETRY_COUNT",
		0x50: "ERR_SOURCE_FILE_OPEN_FAIL",
		0x51: "ERR_TARGET_FILE_IS_EXIST",
		0x52: "ERR_TARGET_FILE_OPEN_FAIL",
		0x54: "ERR_ENC_STREAM_FAIL",
		0x58: "ERR_DEC_STREAM_FAIL",
		0x64: "ERR_FFE_CMD_ABORT",
		0xFE: "MX_LICENSE_INVALID",
	}

	if msg, ok := errMap[code]; ok {
		return msg
	}

	return "UNKNOWN"
}
