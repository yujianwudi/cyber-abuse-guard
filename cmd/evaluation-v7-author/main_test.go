package main

import "testing"

func TestIntroduceTypoAlwaysChangesText(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"Keep this conceptual and non-operational.",
		"Review the authorized backup procedure.",
		"安全审查请求",
		"",
	} {
		if got := introduceTypo(input); got == input {
			t.Fatalf("introduceTypo(%q) was a no-op", input)
		}
	}
}
