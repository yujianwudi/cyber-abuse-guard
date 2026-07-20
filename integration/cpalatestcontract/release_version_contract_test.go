package cpalatestcontract

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginstore"
)

const (
	exactGuardVersion       = "0.15"
	exactGuardReleaseTag    = "v0.15"
	exactGuardRCVersion     = "0.15-rc.4"
	exactGuardRCReleaseTag  = "v0.15-rc.4"
	unsupportedVersionAlias = "0.15.0"
	guardPluginID           = "cyber-abuse-guard"
)

func TestExactGuardV015PluginStoreContract(t *testing.T) {
	profile := selectedCPACompatibilityProfile(t)

	version, errVersion := pluginstore.ReleaseVersion(pluginstore.Release{TagName: exactGuardReleaseTag})
	if errVersion != nil {
		t.Fatalf("%s ReleaseVersion(%q) error = %v", profile.Version, exactGuardReleaseTag, errVersion)
	}
	if version != exactGuardVersion {
		t.Fatalf("%s ReleaseVersion(%q) = %q, want %q", profile.Version, exactGuardReleaseTag, version, exactGuardVersion)
	}

	aliasVersion, errAlias := pluginstore.ReleaseVersion(pluginstore.Release{TagName: "v" + unsupportedVersionAlias})
	if errAlias == nil && aliasVersion == exactGuardVersion {
		t.Fatalf("%s silently normalized unsupported alias %q to exact project version %q", profile.Version, unsupportedVersionAlias, exactGuardVersion)
	}

	archiveName := pluginstore.ArchiveName(guardPluginID, version, "linux", "amd64")
	wantArchiveName := "cyber-abuse-guard_0.15_linux_amd64.zip"
	if archiveName != wantArchiveName {
		t.Fatalf("%s ArchiveName() = %q, want %q", profile.Version, archiveName, wantArchiveName)
	}
	aliasArchiveName := pluginstore.ArchiveName(guardPluginID, unsupportedVersionAlias, "linux", "amd64")
	if aliasArchiveName == archiveName {
		t.Fatalf("%s ArchiveName() treats unsupported alias %q as exact version %q", profile.Version, unsupportedVersionAlias, exactGuardVersion)
	}

	exactLibraryName := "cyber-abuse-guard-v0.15.so"
	archiveData := makeReleaseVersionContractArchive(t, exactLibraryName)
	pluginsDir := t.TempDir()
	result, errInstall := pluginstore.InstallArchive(archiveData, pluginstore.Plugin{
		ID:      guardPluginID,
		Version: version,
	}, pluginstore.InstallOptions{
		PluginsDir: pluginsDir,
		GOOS:       "linux",
		GOARCH:     "amd64",
	})
	if errInstall != nil {
		t.Fatalf("%s InstallArchive() error = %v", profile.Version, errInstall)
	}
	wantTarget := filepath.Join(pluginsDir, "linux", "amd64", exactLibraryName)
	if result.Version != exactGuardVersion || result.Path != wantTarget {
		t.Fatalf("%s InstallArchive() result = %#v, want version=%q path=%q", profile.Version, result, exactGuardVersion, wantTarget)
	}

	aliasLibraryName := "cyber-abuse-guard-v0.15.0.so"
	_, errAliasInstall := pluginstore.InstallArchive(
		makeReleaseVersionContractArchive(t, aliasLibraryName),
		pluginstore.Plugin{ID: guardPluginID, Version: exactGuardVersion},
		pluginstore.InstallOptions{PluginsDir: t.TempDir(), GOOS: "linux", GOARCH: "amd64"},
	)
	if errAliasInstall == nil {
		t.Fatalf("%s accepted unsupported alias library %q for exact project version %q", profile.Version, aliasLibraryName, exactGuardVersion)
	}
	if !strings.Contains(errAliasInstall.Error(), exactLibraryName) {
		t.Fatalf("%s alias rejection error = %v, want exact target library %q", profile.Version, errAliasInstall, exactLibraryName)
	}

	t.Logf("CPA %s exact release contract PASS: tag=%s version=%s archive=%s target=%s alias_version=%q alias_release_error=%v",
		profile.Version, exactGuardReleaseTag, exactGuardVersion, archiveName, exactLibraryName, aliasVersion, errAlias)
}

func TestExactGuardV015RC4PluginStoreContract(t *testing.T) {
	profile := selectedCPACompatibilityProfile(t)

	version, errVersion := pluginstore.ReleaseVersion(pluginstore.Release{TagName: exactGuardRCReleaseTag})
	if errVersion != nil {
		t.Fatalf("%s ReleaseVersion(%q) error = %v", profile.Version, exactGuardRCReleaseTag, errVersion)
	}
	if version != exactGuardRCVersion {
		t.Fatalf("%s ReleaseVersion(%q) = %q, want %q", profile.Version, exactGuardRCReleaseTag, version, exactGuardRCVersion)
	}

	archiveName := pluginstore.ArchiveName(guardPluginID, version, "linux", "amd64")
	wantArchiveName := "cyber-abuse-guard_0.15-rc.4_linux_amd64.zip"
	if archiveName != wantArchiveName {
		t.Fatalf("%s ArchiveName() = %q, want %q", profile.Version, archiveName, wantArchiveName)
	}

	libraryName := "cyber-abuse-guard-v0.15-rc.4.so"
	archiveData := makeReleaseVersionContractArchive(t, libraryName)
	pluginsDir := t.TempDir()
	result, errInstall := pluginstore.InstallArchive(archiveData, pluginstore.Plugin{
		ID:      guardPluginID,
		Version: version,
	}, pluginstore.InstallOptions{
		PluginsDir: pluginsDir,
		GOOS:       "linux",
		GOARCH:     "amd64",
	})
	if errInstall != nil {
		t.Fatalf("%s InstallArchive() error = %v", profile.Version, errInstall)
	}
	wantTarget := filepath.Join(pluginsDir, "linux", "amd64", libraryName)
	if result.Version != exactGuardRCVersion || result.Path != wantTarget {
		t.Fatalf("%s InstallArchive() result = %#v, want version=%q path=%q", profile.Version, result, exactGuardRCVersion, wantTarget)
	}

	t.Logf("CPA %s RC release contract PASS: tag=%s version=%s archive=%s target=%s",
		profile.Version, exactGuardRCReleaseTag, exactGuardRCVersion, archiveName, libraryName)
}

func makeReleaseVersionContractArchive(t *testing.T, libraryName string) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: libraryName, Method: zip.Store}
	header.SetMode(0o755)
	handle, errCreate := writer.CreateHeader(header)
	if errCreate != nil {
		t.Fatalf("create release-version contract archive entry: %v", errCreate)
	}
	if _, errWrite := handle.Write([]byte("synthetic Linux shared-object bytes")); errWrite != nil {
		t.Fatalf("write release-version contract archive entry: %v", errWrite)
	}
	if errClose := writer.Close(); errClose != nil {
		t.Fatalf("close release-version contract archive: %v", errClose)
	}
	return buffer.Bytes()
}
