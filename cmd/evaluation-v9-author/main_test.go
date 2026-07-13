package main

import (
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
)

func TestRecoversAuthoredSemantic(t *testing.T) {
	t.Parallel()
	const intended = "Preserve this uniquely authored security request with all material details."
	if !recoversAuthoredSemantic(extract.Result{Parts: []string{"wrapper text\n" + intended}}, intended) {
		t.Fatal("authored semantic text was not recognized")
	}
	if recoversAuthoredSemantic(extract.Result{Parts: []string{"wrapper metadata and a unique id only"}}, intended) {
		t.Fatal("wrapper-only extraction must not satisfy semantic recovery")
	}
}
