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
	cpaLatestPluginHostPackage = cpaLatestModulePath + "/internal/pluginhost"
	cpaLatestFixtureSHA256     = "9d8b420cac74ea54bb54753269bdebf5e9fbc0f8c0192034a8ea4dda83adbb80"

	cpaCompatibilityProfileEnv = "CPA_COMPAT_PROFILE"
	cpaCompatibilityModfileEnv = "CPA_COMPAT_MODFILE"
	cpaCompatibilityCommitEnv  = "CPA_COMPAT_EXPECTED_COMMIT"
	cpaPrimaryProfile          = "primary"
	cpaBackwardProfile         = "backward"
)

type cpaCompatibilityProfile struct {
	Name       string
	Version    string
	Commit     string
	ModuleSum  string
	GoModSum   string
	MustLatest bool
}

var cpaCompatibilityProfiles = map[string]cpaCompatibilityProfile{
	cpaPrimaryProfile: {
		Name:       cpaPrimaryProfile,
		Version:    "v7.2.80",
		Commit:     "09da52ad509e2c18e7b9540db3b98c2214c280aa",
		ModuleSum:  "h1:QIa5T/KYvJACHVPPRzXcRwq/HLpbwWYJYpZAC1eY2WA=",
		GoModSum:   "h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=",
		MustLatest: true,
	},
	cpaBackwardProfile: {
		Name:       cpaBackwardProfile,
		Version:    "v7.2.79",
		Commit:     "b6ce0beecd31dff389d3190f7db6d7a1d4ce0e7e",
		ModuleSum:  "h1:/2s9euOTOeKUCIPWjHdCsll9vUHkJ/H2bq25Da3DQrg=",
		GoModSum:   "h1:ytvZNWbCv7PrAyR80+RKsDJPODsdL6qxyFaXDBNZdqs=",
		MustLatest: false,
	},
}

var latestCriticalCPAHostTests = []string{
	"TestDecodeEnvelopeResultPreservesPluginHTTPStatus",
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
	profile := selectedCPACompatibilityProfile(t)
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

	moduleCopy := filepath.Join(t.TempDir(), "cpa-"+profile.Version)
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
	profile := selectedCPACompatibilityProfile(t)
	goBinary, errLookPath := exec.LookPath("go")
	if errLookPath != nil {
		t.Fatalf("locate go tool: %v", errLookPath)
	}
	sourceModfile := strings.TrimSpace(os.Getenv(cpaCompatibilityModfileEnv))
	if sourceModfile == "" {
		sourceModfile = "go.mod"
	}
	if !filepath.IsAbs(sourceModfile) {
		absoluteModfile, errAbs := filepath.Abs(sourceModfile)
		if errAbs != nil {
			t.Fatalf("resolve CPA compatibility modfile: %v", errAbs)
		}
		sourceModfile = absoluteModfile
	}
	if filepath.Ext(sourceModfile) != ".mod" {
		t.Fatalf("CPA compatibility modfile must end in .mod: %s", sourceModfile)
	}
	moduleInfo, errModuleInfo := os.Lstat(sourceModfile)
	if errModuleInfo != nil {
		t.Fatalf("stat CPA compatibility modfile: %v", errModuleInfo)
	}
	if !moduleInfo.Mode().IsRegular() || moduleInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("CPA compatibility modfile must be a regular non-symlink file: %s", sourceModfile)
	}
	sourceSumfile := strings.TrimSuffix(sourceModfile, ".mod") + ".sum"
	sumInfo, errSumInfo := os.Lstat(sourceSumfile)
	if errSumInfo != nil {
		t.Fatalf("stat CPA compatibility sumfile: %v", errSumInfo)
	}
	if !sumInfo.Mode().IsRegular() || sumInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("CPA compatibility sumfile must be a regular non-symlink file: %s", sourceSumfile)
	}
	moduleData, errReadModule := os.ReadFile(sourceModfile)
	if errReadModule != nil {
		t.Fatalf("read CPA compatibility module: %v", errReadModule)
	}
	moduleSumData, errReadModuleSum := os.ReadFile(sourceSumfile)
	if errReadModuleSum != nil {
		t.Fatalf("read CPA compatibility checksums: %v", errReadModuleSum)
	}
	temporaryModule := filepath.Join(t.TempDir(), profile.Name+"-host-contract.mod")
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
	if module.Path != cpaLatestModulePath || module.Version != profile.Version || strings.TrimSpace(module.Dir) == "" {
		t.Fatalf("resolved latest CPA module = %s@%s dir=%q, want %s@%s with source dir",
			module.Path, module.Version, module.Dir, cpaLatestModulePath, profile.Version)
	}
	if module.Sum != profile.ModuleSum || module.GoModSum != profile.GoModSum {
		t.Fatalf("resolved latest CPA checksums = module %q go.mod %q, want module %q go.mod %q",
			module.Sum, module.GoModSum, profile.ModuleSum, profile.GoModSum)
	}
	t.Logf("CPA compatibility source contract: profile=%s %s@%s commit=%s sum=%s go_mod_sum=%s latest_required=%t",
		profile.Name, module.Path, module.Version, profile.Commit, module.Sum, module.GoModSum, profile.MustLatest)
	return goBinary, moduleArguments, module
}

func selectedCPACompatibilityProfile(t *testing.T) cpaCompatibilityProfile {
	t.Helper()
	name := strings.TrimSpace(os.Getenv(cpaCompatibilityProfileEnv))
	if name == "" {
		name = cpaPrimaryProfile
	}
	profile, ok := cpaCompatibilityProfiles[name]
	if !ok {
		t.Fatalf("unsupported %s=%q; allowed values are %q and %q",
			cpaCompatibilityProfileEnv, name, cpaPrimaryProfile, cpaBackwardProfile)
	}
	if expectedCommit := strings.TrimSpace(os.Getenv(cpaCompatibilityCommitEnv)); expectedCommit != "" && expectedCommit != profile.Commit {
		t.Fatalf("%s=%q does not match pinned %s commit %s",
			cpaCompatibilityCommitEnv, expectedCommit, profile.Name, profile.Commit)
	}
	return profile
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
