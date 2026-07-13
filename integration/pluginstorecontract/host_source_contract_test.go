package pluginstorecontract

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	cpaModulePath        = "github.com/router-for-me/CLIProxyAPI/v7"
	cpaPinnedVersion     = "v7.2.72"
	cpaPluginHostPackage = cpaModulePath + "/internal/pluginhost"
)

// TestOfficialCPAHostRoutingSourceContract runs the routing contract tests
// shipped by the pinned CPA module. It deliberately tests the official source
// package instead of copying the host's priority, fail-open, fuse, target
// validation, or executor-readiness implementation into this repository.
func TestOfficialCPAHostRoutingSourceContract(t *testing.T) {
	goBinary, errLookPath := exec.LookPath("go")
	if errLookPath != nil {
		t.Fatalf("locate go tool: %v", errLookPath)
	}

	moduleData, errReadModule := os.ReadFile("go.mod")
	if errReadModule != nil {
		t.Fatalf("read pinned module definition: %v", errReadModule)
	}
	moduleSumData, errReadModuleSum := os.ReadFile("go.sum")
	if errReadModuleSum != nil {
		t.Fatalf("read pinned module checksums: %v", errReadModuleSum)
	}
	temporaryModule := t.TempDir() + "/host-contract.mod"
	if errWriteModule := os.WriteFile(temporaryModule, moduleData, 0o600); errWriteModule != nil {
		t.Fatalf("write temporary module definition: %v", errWriteModule)
	}
	temporaryModuleSum := strings.TrimSuffix(temporaryModule, ".mod") + ".sum"
	if errWriteModuleSum := os.WriteFile(temporaryModuleSum, moduleSumData, 0o600); errWriteModuleSum != nil {
		t.Fatalf("write temporary module checksums: %v", errWriteModuleSum)
	}
	moduleArguments := []string{"-mod=mod", "-modfile=" + temporaryModule}

	moduleVersion := runGoCommand(t, goBinary,
		"list", moduleArguments[0], moduleArguments[1], "-m", "-f", "{{.Version}}", cpaModulePath,
	)
	if got := strings.TrimSpace(moduleVersion); got != cpaPinnedVersion {
		t.Fatalf("resolved CPA module version = %q, want %q", got, cpaPinnedVersion)
	}

	const testPattern = `^(TestHostRouteModel.*|TestSortRecordsPriorityDescendingAndIDTieBreak)$`
	runGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", testPattern,
		cpaPluginHostPackage,
	)
}

func runGoCommand(t *testing.T, goBinary string, arguments ...string) string {
	t.Helper()

	command := exec.Command(goBinary, arguments...)
	command.Env = append(os.Environ(), "GOWORK=off")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if errRun := command.Run(); errRun != nil {
		t.Fatalf("%s %s failed: %v\n%s", goBinary, strings.Join(arguments, " "), errRun, output.String())
	}
	t.Logf("%s", output.String())
	return output.String()
}
