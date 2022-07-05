package common

import (
	"github.com/pingcap/failpoint"
)

//OpenAssert open assert
func OpenAssert() {
	_ = failpoint.Enable("github.com/meshplus/crypto/test/runtime_assert", `return("")`)
}

//CloseAssert close assert
func CloseAssert() {
	_ = failpoint.Disable("github.com/meshplus/crypto/test/runtime_assert")
}

//Assert assert true
func Assert(f func() bool) {
	failpoint.Inject("runtime_assert", func(_ failpoint.Value) {
		if !f() {
			panic("assert true")
		}
	})
}
