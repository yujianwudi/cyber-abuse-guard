package subject

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestControllerCooldownManualBlockAndSafeRequests(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	hash := riskHash("subject-one")

	if decision := controller.Evaluate(hash, 10); decision.Blocked || decision.Score != 0 {
		t.Fatalf("safe initial request = %#v", decision)
	}
	if controller.Count() != 0 {
		t.Fatal("safe requests should not allocate risk state")
	}

	first := controller.Evaluate(hash, 60)
	if first.Blocked || first.Score != 60 || first.Multiplier != 1 || first.RepeatCount != 1 {
		t.Fatalf("first risky request = %#v", first)
	}
	second := controller.Evaluate(hash, 60)
	if !second.Blocked || second.Reason != ReasonCooldown || second.Score != 150 || second.Multiplier != 1.5 || second.RepeatCount != 2 {
		t.Fatalf("second risky request = %#v", second)
	}

	// Cooldown and manual states are scoped to new risky requests. A normal
	// request must remain usable rather than turning one false positive into a
	// permanent account denial.
	safe := controller.Evaluate(hash, 5)
	if safe.Blocked || safe.Reason != ReasonSafe || !safe.CooldownUntil.Equal(second.CooldownUntil) {
		t.Fatalf("safe request during cooldown = %#v", safe)
	}

	clock.Add(61 * time.Minute)
	afterWindow := controller.Evaluate(hash, 40)
	if afterWindow.Blocked || afterWindow.Score != 40 || afterWindow.RepeatCount != 1 {
		t.Fatalf("request after rolling window = %#v", afterWindow)
	}

	manualHash := riskHash("manual")
	if got := controller.Evaluate(manualHash, 100); got.Blocked {
		t.Fatalf("first manual-threshold hit = %#v", got)
	}
	manual := controller.Evaluate(manualHash, 100)
	if !manual.Blocked || manual.Reason != ReasonManualBlock || !manual.ManualBlocked || manual.Score != 250 {
		t.Fatalf("manual block decision = %#v", manual)
	}
	if got := controller.Evaluate(manualHash, 1); got.Blocked || got.Reason != ReasonSafe || !got.ManualBlocked {
		t.Fatalf("safe request under manual state = %#v", got)
	}
	if !controller.Unblock(manualHash) {
		t.Fatal("Unblock() returned false for an existing subject")
	}
	if controller.Unblock(manualHash) {
		t.Fatal("Unblock() returned true for an absent subject")
	}
	if got := controller.Evaluate(manualHash, 40); got.Blocked || got.Score != 40 {
		t.Fatalf("risk history survived Unblock(): %#v", got)
	}
}

func TestControllerRollingLinearDecayAndRepeatBound(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	hash := riskHash("decay")
	if got := controller.Evaluate(hash, 100); got.Score != 100 {
		t.Fatalf("first score = %#v", got)
	}
	clock.Add(30 * time.Minute)
	state, ok := controller.Snapshot(hash)
	if !ok || state.Score != 50 {
		t.Fatalf("half-window Snapshot() = (%#v, %v)", state, ok)
	}

	// Repeat multipliers grow but are explicitly bounded.
	for i := 0; i < 10; i++ {
		decision := controller.Evaluate(riskHash("repeat"), 35)
		if decision.Multiplier > 3 {
			t.Fatalf("repeat multiplier escaped bound: %#v", decision)
		}
	}
}

func TestControllerConcurrentSafety(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	hash := riskHash("concurrent")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = controller.Evaluate(hash, 35)
		}()
	}
	wg.Wait()
	if controller.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", controller.Count())
	}
	state, ok := controller.Snapshot(hash)
	if !ok || !state.ManualBlocked || state.HitCount != 100 {
		t.Fatalf("concurrent State = (%#v, %v)", state, ok)
	}
	if !controller.Unblock(hash) || controller.Count() != 0 {
		t.Fatalf("concurrent Unblock failed; count=%d", controller.Count())
	}
}

func TestControllerRejectsUnsafeConfig(t *testing.T) {
	t.Parallel()

	valid := Config{
		Enabled:          true,
		Window:           time.Hour,
		AuditThreshold:   35,
		CooldownScore:    150,
		ManualBlockScore: 250,
		Cooldown:         30 * time.Minute,
		RepeatMultiplier: 1.5,
		MaxMultiplier:    3,
	}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"window", func(c *Config) { c.Window = 0 }},
		{"audit threshold", func(c *Config) { c.AuditThreshold = 0 }},
		{"cooldown score", func(c *Config) { c.CooldownScore = 0 }},
		{"threshold order", func(c *Config) { c.ManualBlockScore = c.CooldownScore }},
		{"cooldown", func(c *Config) { c.Cooldown = 0 }},
		{"repeat multiplier", func(c *Config) { c.RepeatMultiplier = .5 }},
		{"max multiplier", func(c *Config) { c.MaxMultiplier = 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.edit(&cfg)
			if _, err := NewController(cfg); err == nil {
				t.Fatalf("NewController(%s) succeeded: %#v", tc.name, cfg)
			}
		})
	}
}

func TestControllerNeverStoresPlaintextSubject(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	decision := controller.Evaluate("plaintext-api-key-canary", 1000)
	if decision.Blocked || decision.Reason != ReasonInvalidHash || decision.SubjectHash != "" {
		t.Fatalf("plaintext decision = %#v", decision)
	}
	if controller.Count() != 0 {
		t.Fatal("controller retained a plaintext subject")
	}
}

func newTestController(t *testing.T, clock *testClock) *Controller {
	t.Helper()
	controller, err := NewController(Config{
		Enabled:          true,
		Window:           time.Hour,
		AuditThreshold:   35,
		CooldownScore:    150,
		ManualBlockScore: 250,
		Cooldown:         30 * time.Minute,
		RepeatMultiplier: 1.5,
		MaxMultiplier:    3,
		Now:              clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func (c *testClock) String() string {
	return fmt.Sprint(c.Now())
}

func riskHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(sum[:])
}
