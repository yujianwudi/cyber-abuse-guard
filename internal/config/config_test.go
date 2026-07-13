package config

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultMatchesTaskBook(t *testing.T) {
	t.Parallel()

	got := Default()
	if !got.Enabled || got.Priority != 300 || got.Mode != ModeBalanced {
		t.Fatalf("top-level defaults = %#v", got)
	}
	if got.MaxScanBytes != 262144 || got.MaxJSONDepth != 32 || got.MaxTextParts != 512 {
		t.Fatalf("extraction defaults = %d/%d/%d", got.MaxScanBytes, got.MaxJSONDepth, got.MaxTextParts)
	}
	if got.OpaqueMediaPolicy != OpaqueMediaPolicyAuto || got.EffectiveOpaqueMediaPolicy() != OpaqueMediaPolicyAudit {
		t.Fatalf("balanced opaque-media default = explicit:%q effective:%q", got.OpaqueMediaPolicy, got.EffectiveOpaqueMediaPolicy())
	}
	if got.Thresholds != (Thresholds{Audit: 35, BalancedBlock: 60, HardBlock: 80}) {
		t.Fatalf("threshold defaults = %#v", got.Thresholds)
	}
	if got.AllowContext != (AllowContext{
		CTF: true, Lab: true, AuthorizedTesting: true, DefensiveAnalysis: true,
		Remediation: true, MalwareStaticAnalysis: true,
	}) {
		t.Fatalf("allow-context defaults = %#v", got.AllowContext)
	}
	if got.HardBlockEvenIfAuthorized != (HardBlockEvenIfAuthorized{
		CredentialTheft: true, PhishingDeployment: true,
		RansomwareDeployment: true, DataExfiltration: true,
	}) {
		t.Fatalf("hard-block defaults = %#v", got.HardBlockEvenIfAuthorized)
	}
	if got.SubjectControl != (SubjectControl{
		Enabled: true, MaxSubjects: 10000, WindowMinutes: 60, CooldownScore: 150,
		ManualBlockScore: 250, CooldownMinutes: 30,
	}) {
		t.Fatalf("subject-control defaults = %#v", got.SubjectControl)
	}
	if got.Audit != (Audit{
		Enabled: true, DataDir: "", RetentionDays: 30, MaxDBMB: 256,
		LogRequestHash: true, LogSubjectHash: true, LogRuleIDs: true,
		LogCategory: true, LogOriginalText: false, BackupBeforeMigration: true,
		MaxMigrationBackups: 3,
	}) {
		t.Fatalf("audit defaults = %#v", got.Audit)
	}
	if got.TrustedProxy.Enabled || got.TrustedProxy.Header != "X-Forwarded-For" || len(got.TrustedProxy.CIDRs) != 0 {
		t.Fatalf("trusted-proxy defaults = %#v", got.TrustedProxy)
	}
	if got.Classifier != (Classifier{Enabled: false, Endpoint: "", TimeoutMS: 300, FailMode: ClassifierFailRulesOnly}) {
		t.Fatalf("classifier defaults = %#v", got.Classifier)
	}
	if err := Validate(got); err != nil {
		t.Fatalf("Validate(Default()) = %v", err)
	}
}

func TestParseAppliesDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	data := []byte(`
mode: strict
opaque_media_policy: allow
max_scan_bytes: 131072
allow_context:
  ctf: false
subject_control:
  window_minutes: 120
audit:
  data_dir: ./plugin-data
  log_request_hash: false
trusted_proxy:
  enabled: false
  header: X-Real-IP
  cidrs:
    - 10.0.0.0/8
classifier:
  enabled: false
  endpoint: http://127.0.0.1:8090/classify
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.Mode != ModeStrict || got.MaxScanBytes != 131072 {
		t.Fatalf("overrides not applied: %#v", got)
	}
	if got.OpaqueMediaPolicy != OpaqueMediaPolicyAllow || got.EffectiveOpaqueMediaPolicy() != OpaqueMediaPolicyAllow {
		t.Fatalf("opaque media override not applied: %#v", got)
	}
	if got.AllowContext.CTF || !got.AllowContext.Lab {
		t.Fatalf("boolean override/default = %#v", got.AllowContext)
	}
	if got.SubjectControl.WindowMinutes != 120 || got.SubjectControl.CooldownScore != 150 {
		t.Fatalf("nested defaults = %#v", got.SubjectControl)
	}
	if got.Audit.DataDir != "./plugin-data" || got.Audit.LogRequestHash || !got.Audit.LogSubjectHash {
		t.Fatalf("audit override/default = %#v", got.Audit)
	}
	if !reflect.DeepEqual(got.TrustedProxy.CIDRs, []string{"10.0.0.0/8"}) {
		t.Fatalf("CIDRs = %#v", got.TrustedProxy.CIDRs)
	}
}

func TestParseAcceptsAllModes(t *testing.T) {
	t.Parallel()

	for _, mode := range []Mode{ModeOff, ModeObserve, ModeAudit, ModeBalanced, ModeStrict} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			got, err := Parse([]byte("mode: " + string(mode) + "\n"))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got.Mode != mode {
				t.Fatalf("Mode = %q, want %q", got.Mode, mode)
			}
		})
	}
}

func TestParseRejectsMalformedOrAmbiguousYAML(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"unknown field":    []byte("unknown_option: true\n"),
		"wrong type":       []byte("max_scan_bytes: many\n"),
		"duplicate key":    []byte("mode: audit\nmode: strict\n"),
		"multiple docs":    []byte("mode: audit\n---\nmode: strict\n"),
		"YAML alias":       []byte("mode: &mode balanced\ncopy: *mode\n"),
		"YAML deep flow":   []byte("mode: " + strings.Repeat("[", maxYAMLFlowDepth+1) + "balanced\n"),
		"invalid UTF-8":    {0xff, 0xfe, 0xfd},
		"oversized config": bytes.Repeat([]byte("#"), MaxConfigBytes+1),
	}
	for name, data := range tests {
		data := data
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(data); err == nil {
				t.Fatal("Parse() error = nil")
			}
		})
	}
}

func TestValidateThresholdsAndRanges(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Config){
		"invalid mode":                func(c *Config) { c.Mode = "maximum" },
		"opaque media policy":         func(c *Config) { c.OpaqueMediaPolicy = "download" },
		"scan too small":              func(c *Config) { c.MaxScanBytes = 0 },
		"scan too large":              func(c *Config) { c.MaxScanBytes = MaxAllowedScanBytes + 1 },
		"depth too large":             func(c *Config) { c.MaxJSONDepth = MaxAllowedJSONDepth + 1 },
		"parts too large":             func(c *Config) { c.MaxTextParts = MaxAllowedTextParts + 1 },
		"threshold range":             func(c *Config) { c.Thresholds.HardBlock = 101 },
		"threshold order":             func(c *Config) { c.Thresholds.BalancedBlock = c.Thresholds.Audit },
		"subject capacity":            func(c *Config) { c.SubjectControl.MaxSubjects = maxSubjectEntries + 1 },
		"subject score order":         func(c *Config) { c.SubjectControl.ManualBlockScore = c.SubjectControl.CooldownScore },
		"retention":                   func(c *Config) { c.Audit.RetentionDays = -1 },
		"original text logging":       func(c *Config) { c.Audit.LogOriginalText = true },
		"migration backups":           func(c *Config) { c.Audit.MaxMigrationBackups = 11 },
		"backup count zero":           func(c *Config) { c.Audit.BackupBeforeMigration = true; c.Audit.MaxMigrationBackups = 0 },
		"persistence without subject": func(c *Config) { c.SubjectControl.Persistence = true; c.SubjectControl.Enabled = false },
		"persistence without audit":   func(c *Config) { c.SubjectControl.Persistence = true; c.Audit.Enabled = false },
		"persistence capacity": func(c *Config) {
			c.SubjectControl.Persistence = true
			c.SubjectControl.MaxSubjects = maxPersistedSubjects + 1
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			mutate(&cfg)
			if err := Validate(cfg); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestOpaqueMediaPolicyModeAwareDefaults(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		mode Mode
		want OpaqueMediaPolicy
	}{
		{mode: ModeOff, want: OpaqueMediaPolicyAllow},
		{mode: ModeObserve, want: OpaqueMediaPolicyAudit},
		{mode: ModeAudit, want: OpaqueMediaPolicyAudit},
		{mode: ModeBalanced, want: OpaqueMediaPolicyAudit},
		{mode: ModeStrict, want: OpaqueMediaPolicyBlock},
	} {
		cfg := Default()
		cfg.Mode = testCase.mode
		cfg.OpaqueMediaPolicy = OpaqueMediaPolicyAuto
		if got := cfg.EffectiveOpaqueMediaPolicy(); got != testCase.want {
			t.Errorf("mode %s effective policy=%s, want %s", testCase.mode, got, testCase.want)
		}
	}
}

func TestValidateAuditDataDir(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"../events", `safe\..\events`, "safe/../../events", "bad\x00path", "https://example.test/events"} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.Audit.DataDir = path
			if err := Validate(cfg); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}

	for _, path := range []string{"", "./plugin-data", "/var/lib/cyber-abuse-guard", `C:\ProgramData\cyber-abuse-guard`, "~/.cli-proxy-api/plugins/cyber-abuse-guard"} {
		path := path
		t.Run("valid "+path, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.Audit.DataDir = path
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestValidateTrustedProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		cidrs  []string
		valid  bool
	}{
		{name: "valid disabled v4 and v6", header: "X-Real-IP", cidrs: []string{"10.0.0.0/8", "fd00::/32"}, valid: true},
		{name: "disabled may omit cidr", header: "X-Real-IP", cidrs: nil, valid: true},
		{name: "bad cidr", header: "X-Real-IP", cidrs: []string{"10.0.0.1"}},
		{name: "header injection", header: "X-Real-IP\r\nX-Evil", cidrs: []string{"10.0.0.0/8"}},
		{name: "bad header token", header: "Forwarded IP", cidrs: []string{"10.0.0.0/8"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.TrustedProxy.Enabled = false
			cfg.TrustedProxy.Header = tt.header
			cfg.TrustedProxy.CIDRs = tt.cidrs
			err := Validate(cfg)
			if tt.valid && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}

	cfg := Default()
	cfg.TrustedProxy.Enabled = true
	cfg.TrustedProxy.CIDRs = []string{"10.0.0.0/8"}
	if err := Validate(cfg); err == nil {
		t.Fatal("trusted proxy activation must be rejected until CPA exposes a trusted peer address")
	}
}

func TestValidateClassifierEndpoint(t *testing.T) {
	t.Parallel()

	valid := []string{
		"http://localhost:8090/classify",
		"http://127.0.0.1:8090/classify",
		"http://[::1]:8090/classify",
		"http://10.1.2.3/classify",
		"https://192.168.1.10/classify",
		"http://[fd00::1]/classify",
	}
	for _, endpoint := range valid {
		endpoint := endpoint
		t.Run("valid "+endpoint, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.Classifier.Enabled = false
			cfg.Classifier.Endpoint = endpoint
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}

	invalid := []string{
		"https://example.com/classify", "http://8.8.8.8/classify",
		"file:///tmp/classify.sock", "http://user:pass@127.0.0.1/classify",
		"http://127.0.0.1:bad/classify", "http://169.254.169.254/latest/meta-data",
	}
	for _, endpoint := range invalid {
		endpoint := endpoint
		t.Run("invalid "+endpoint, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.Classifier.Enabled = false
			cfg.Classifier.Endpoint = endpoint
			if err := Validate(cfg); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}

	cfg := Default()
	cfg.Classifier.Endpoint = "https://example.com/classify"
	if err := Validate(cfg); err == nil {
		t.Fatal("disabled classifier retained an unsafe public endpoint")
	}

	cfg = Default()
	cfg.Classifier.Enabled = true
	cfg.Classifier.Endpoint = "http://127.0.0.1:8090/classify"
	if err := Validate(cfg); err == nil {
		t.Fatal("this release must reject classifier.enabled instead of silently ignoring it")
	}
}

func TestValidateClassifierFailMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Classifier.FailMode = "allow"
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func TestParseEmptyUsesDefaults(t *testing.T) {
	t.Parallel()

	for _, data := range [][]byte{nil, []byte("# use secure defaults\n")} {
		got, err := Parse(data)
		if err != nil {
			t.Fatalf("Parse(%q) error = %v", data, err)
		}
		if !reflect.DeepEqual(got, Default()) {
			t.Fatalf("Parse(%q) = %#v, want defaults", data, got)
		}
	}
}

func FuzzConfigParser(f *testing.F) {
	seeds := [][]byte{
		nil,
		[]byte("mode: balanced\n"),
		[]byte("thresholds:\n  audit: 35\n  balanced_block: 60\n  hard_block: 80\n"),
		[]byte("classifier:\n  enabled: true\n  endpoint: http://127.0.0.1:8090/classify\n"),
		[]byte("trusted_proxy:\n  enabled: true\n  cidrs: [10.0.0.0/8]\n"),
		[]byte("mode: [broken\n"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(data)
		if err == nil {
			if err := Validate(cfg); err != nil {
				t.Fatalf("Parse returned invalid config: %v", err)
			}
		}
	})
}

func TestErrorsAreClassifiable(t *testing.T) {
	t.Parallel()

	_, err := Parse(bytes.Repeat([]byte("#"), MaxConfigBytes+1))
	if !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("error = %v, want ErrConfigTooLarge", err)
	}
	_, err = Parse([]byte("mode: impossible\n"))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Fatal("error message is empty")
	}
}
