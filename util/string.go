package util

func Int8Slice2String(s []int8) string {
	uintSlice := make([]byte, 0)
	for i := range s {
		if s[i] == 0 {
			break
		}
		uintSlice = append(uintSlice, byte(s[i]))
	}
	return string(uintSlice)
}
