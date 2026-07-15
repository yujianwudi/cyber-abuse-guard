package cpalatestcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	cpaLatestModulePath        = "github.com/router-for-me/CLIProxyAPI/v7"
	cpaLatestVersion           = "v7.2.80"
	cpaLatestCommit            = "09da52ad509e2c18e7b9540db3b98c2214c280aa"
	cpaLatestModuleSum         = "h1:QIa5T/KYvJACHVPPRzXcRwq/HLpbwWYJYpZAC1eY2WA="
	cpaLatestGoModSum          = "h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs="
	cpaLatestPluginHostPackage = cpaLatestModulePath + "/internal/pluginhost"
	cpaLatestFixtureSHA256     = "9d8b420cac74ea54bb54753269bdebf5e9fbc0f8c0192034a8ea4dda83adbb80"
)

var latestCriticalCPAHostTests = []string{
	"TestHostRouteModelAllowsExplicitExecutorPluginTarget",
	"TestHostRouteModelClonesPluginMetadata",
	"TestHostRouteModelContinuesAfterUnhandled",
	"TestHostRouteModelDefaultsHandledRouterToOwnExecutor",
	"TestHostRouteModelErrorAndPanicDoNotBreakFallback",
	"TestHostRouteModelPropagatesAvailableProviders",
	"TestHostRouteModelRejectsProviderAndExecutorBothSet",
	"TestHostRouteModelRoutesToBuiltinProvider",
	"TestHostRouteModelSkipsExecutorWithoutProviderIdentifier",
	"TestHostRouteModelSkipsExecutorWithUnsupportedFormats",
	"TestHostRouteModelSkipsOAuthOnlyExecutorTargets",
	"TestHostRouteModelSkipsOriginatingPlugin",
	"TestHostRouteModelSkipsUnavailableBuiltinProvider",
	"TestHostRouteModelSkipsUnavailableExecutorTargets",
	"TestHostRouteModelUsesHighestPriorityFirstMatch",
	"TestSortRecordsPriorityDescendingAndIDTieBreak",
}

type latestResolvedCPAModule struct {
	Path     string
	Version  string
	Dir      string
	Sum      string
	GoModSum string
	Replace  *latestResolvedCPAModule
}

// Compile-time binding proves that the latest public plugin API, including the
// additive UsageRecord.Generate field introduced after v7.2.75, is available.
// The Guard does not register UsagePlugin; this is an API compatibility probe.
var _ = pluginapi.UsageRecord{Generate: true}

func TestLatestCPAOfficialHostRoutingSourceContract(t *testing.T) {
	goBinary, moduleArguments, _ := prepareLatestCPAModule(t)

	listed := runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-list", "^Test", cpaLatestPluginHostPackage,
	)
	listedTests := make(map[string]struct{})
	for _, line := range strings.Split(listed, "\n") {
		name := strings.TrimSpace(line)
		if strings.HasPrefix(name, "Test") && !strings.ContainsAny(name, " \t") {
			listedTests[name] = struct{}{}
		}
	}
	for _, name := range latestCriticalCPAHostTests {
		if _, ok := listedTests[name]; !ok {
			t.Fatalf("latest CPA host package no longer lists required test %q", name)
		}
	}

	exactNames := make([]string, 0, len(latestCriticalCPAHostTests))
	for _, name := range latestCriticalCPAHostTests {
		exactNames = append(exactNames, regexp.QuoteMeta(name))
	}
	runLatestGoCommand(t, goBinary,
		"test", moduleArguments[0], moduleArguments[1], "-count=1", "-v",
		"-run", "^("+strings.Join(exactNames, "|")+")$", cpaLatestPluginHostPackage,
	)
}

func TestLatestCPAHostFailOpenFixtureContract(t *testing.T) {
	goBinary, _, module := prepareLatestCPAModule(t)
	fixturePath, errFixtureAbs := filepath.Abs(filepath.Join("..", "pluginstorecontract", "testfixtures", "host_failopen_overlay_test.go.txt"))
	if errFixtureAbs != nil {
		t.Fatalf("resolve shared Host fixture path: %v", errFixtureAbs)
	}
	fixtureData, errReadFixture := os.ReadFile(fixturePath)
	if errReadFixture != nil {
		t.Fatalf("read shared Host fixture: %v", errReadFixture)
	}
	// Git stores the fixture with LF, while a Windows worktree may materialize
	// it as CRLF. Pin the canonical Git content instead of platform-specific
	// checkout bytes, and write the same canonical source into the module copy.
	fixtureData = bytes.ReplaceAll(fixtureData, []byte("\r\n"), []byte("\n"))
	if bytes.ContainsRune(fixtureData, '\r') {
		t.Fatal("shared Host fixture contains a non-canonical carriage return")
	}
	fixtureHash := sha256.Sum256(fixtureData)
	if actual := hex.EncodeToString(fixtureHash[:]); actual != cpaLatestFixtureSHA256 {
		t.Fatalf("shared Host fixture sha256=%s, want %s", actual, cpaLatestFixtureSHA256)
	}

	moduleCopy := filepath.Join(t.TempDir(), "cpa-v7.2.80")
	if errCopyModule := os.CopyFS(moduleCopy, os.DirFS(module.Dir)); errCopyModule != nil {
		t.Fatalf("copy latest CPA module for Host fixture: %v", errCopyModule)
	}
	targetPath := filepath.Join(moduleCopy, "internal", "pluginhost", "cyber_abuse_guard_host_fixture_test.go")
	if errWriteFixture := os.WriteFile(targetPath, fixtureData, 0o600); errWriteFixture != nil {
		t.Fatalf("write ephemeral Host fixture: %v", errWriteFixture)
	}
	const fixtureTestName = "TestCyberAbuseGuardHostFailOpenFixtureMatrix"
	listed := runLatestGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=readonly", "-list", "^"+fixtureTestName+"$", "./internal/pluginhost",
	)
	if !linePresent(listed, fixtureTestName) {
		t.Fatalf("ephemeral latest CPA Host overlay does not list required test %q", fixtureTestName)
	}
	runLatestGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=readonly", "-count=1", "-v",
		"-run", "^"+fixtureTestName+"$", "./internal/pluginhost",
	)
}

func prepareLatestCPAModule(t *testing.T) (string, []string, latestResolvedCPAModule) {
	t.Helper()
	goBinary, errLookPath := exec.LookPath("go")
	if errLookPath != nil {
		t.Fatalf("locate go tool: %v", errLookPath)
	}
	moduleData, errReadModule := os.ReadFile("go.mod")
	if errReadModule != nil {
		t.Fatalf("read latest contract module: %v", errReadModule)
	}
	moduleSumData, errReadModuleSum := os.ReadFile("go.sum")
	if errReadModuleSum != nil {
		t.Fatalf("read latest contract checksums: %v", errReadModuleSum)
	}
	temporaryModule := filepath.Join(t.TempDir(), "latest-host-contract.mod")
	if errWriteModule := os.WriteFile(temporaryModule, moduleData, 0o600); errWriteModule != nil {
		t.Fatalf("write temporary latest module: %v", errWriteModule)
	}
	temporaryModuleSum := strings.TrimSuffix(temporaryModule, ".mod") + ".sum"
	if errWriteModuleSum := os.WriteFile(temporaryModuleSum, moduleSumData, 0o600); errWriteModuleSum != nil {
		t.Fatalf("write temporary latest checksums: %v", errWriteModuleSum)
	}
	// Official upstream package tests pull their own transitive test graph. Let
	// Go add those checksum-verified entries only to the temporary mod/sum pair;
	// the checked-in latest-contract module remains minimal and tidy-clean.
	moduleArguments := []string{"-mod=mod", "-modfile=" + temporaryModule}

	moduleJSON := runLatestGoJSONCommand(t, goBinary,
		"list", moduleArguments[0], moduleArguments[1], "-m", "-json", cpaLatestModulePath,
	)
	var module latestResolvedCPAModule
	if errUnmarshal := json.Unmarshal([]byte(moduleJSON), &module); errUnmarshal != nil {
		t.Fatalf("decode latest CPA module metadata: %v", errUnmarshal)
	}
	if module.Replace != nil {
		t.Fatal("latest CPA module unexpectedly uses a replacement")
	}
	if module.Path != cpaLatestModulePath || module.Version != cpaLatestVersion || strings.TrimSpace(module.Dir) == "" {
		t.Fatalf("resolved latest CPA module = %s@%s dir=%q, want %s@%s with source dir",
			module.Path, module.Version, module.Dir, cpaLatestModulePath, cpaLatestVersion)
	}
	if module.Sum != cpaLatestModuleSum || module.GoModSum != cpaLatestGoModSum {
		t.Fatalf("resolved latest CPA checksums = module %q go.mod %q, want module %q go.mod %q",
			module.Sum, module.GoModSum, cpaLatestModuleSum, cpaLatestGoModSum)
	}
	t.Logf("latest CPA source contract: %s@%s commit=%s sum=%s go_mod_sum=%s",
		module.Path, module.Version, cpaLatestCommit, module.Sum, module.GoModSum)
	return goBinary, moduleArguments, module
}

func linePresent(output, want string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func runLatestGoCommand(t *testing.T, goBinary string, arguments ...string) string {
	t.Helper()
	return runLatestGoCommandInDir(t, "", goBinary, arguments...)
}

func runLatestGoJSONCommand(t *testing.T, goBinary string, arguments ...string) string {
	t.Helper()
	command := exec.Command(goBinary, arguments...)
	command.Env = append(os.Environ(), "GOWORK=off")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if errRun := command.Run(); errRun != nil {
		t.Fatalf("%s %s failed: %v\nstdout:\n%s\nstderr:\n%s",
			goBinary, strings.Join(arguments, " "), errRun, stdout.String(), stderr.String())
	}
	if stderr.Len() > 0 {
		t.Logf("%s", stderr.String())
	}
	return stdout.String()
}

func runLatestGoCommandInDir(t *testing.T, directory, goBinary string, arguments ...string) string {
	t.Helper()
	command := exec.Command(goBinary, arguments...)
	command.Dir = directory
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
