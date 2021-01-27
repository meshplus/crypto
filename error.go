package crypto

import (
	"encoding/hex"
	"fmt"
)

//ErrNotSupport this algo is not support
var ErrNotSupport = fmt.Errorf("engine: this algo is not support")

//ErrDevice device internal error
func ErrDevice(msg string) error {
	return fmt.Errorf("engine: device internal error: %v", msg)
}

//ErrIndexMissing index missing
func ErrIndexMissing(index []byte) error {
	return fmt.Errorf("engine: index missing: %v", hex.EncodeToString(index))
}
