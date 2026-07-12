package subject

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// Reason is a stable, coarse risk-control outcome. It contains no classifier
// evidence or request content.
type Reason string

const (
	ReasonSafe        Reason = "safe"
	ReasonRisk        Reason = "risk_recorded"
	ReasonCooldown    Reason = "cooldown"
	ReasonManualBlock Reason = "manual_block"
	ReasonDisabled    Reason = "disabled"
	ReasonInvalidHash Reason = "invalid_subject_hash"
)

// Config controls rolling in-memory subject risk.
type Config struct {
	Enabled          bool
	Window           time.Duration
	AuditThreshold   int
	CooldownScore    float64
	ManualBlockScore float64
	Cooldown         time.Duration
	RepeatMultiplier float64
	MaxMultiplier    float64
	Now              func() time.Time
}

// Decision describes the result for the current request. A Blocked result is
// possible only when the current riskScore is at least AuditThreshold.
type Decision struct {
	SubjectHash   string    `json:"subject_hash"`
	Blocked       bool      `json:"blocked"`
	Reason        Reason    `json:"reason"`
	Score         float64   `json:"score"`
	AddedScore    float64   `json:"added_score"`
	Multiplier    float64   `json:"multiplier"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
	ManualBlocked bool      `json:"manual_blocked"`
	RepeatCount   int       `json:"repeat_count"`
}

// State is a secret-free management snapshot for one already-HMACed subject.
type State struct {
	SubjectHash   string    `json:"subject_hash"`
	Score         float64   `json:"score"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
	ManualBlocked bool      `json:"manual_blocked"`
	HitCount      int       `json:"hit_count"`
}

type hit struct {
	at    time.Time
	score float64
}

type entry struct {
	hits          []hit
	cooldownUntil time.Time
	manualBlocked bool
}

// Controller owns concurrent in-memory risk state.
type Controller struct {
	mu          sync.Mutex
	cfg         Config
	entries     map[string]*entry
	evaluations uint64
}

const (
	maxHitsPerSubject = 1024
	sweepEvery        = 256
)

// NewController validates risk-control thresholds before creating state. A
// disabled controller accepts zero-valued thresholds and always allows.
func NewController(cfg Config) (*Controller, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Enabled {
		if err := validateConfig(cfg); err != nil {
			return nil, err
		}
	}
	return &Controller{cfg: cfg, entries: make(map[string]*entry)}, nil
}

// Evaluate records and evaluates one classifier score. Scores below the audit
// threshold are always safe, including while a subject is cooling down or
// manually blocked; this prevents ordinary traffic from being permanently
// denied after a false positive.
func (c *Controller) Evaluate(subjectHash string, riskScore int) Decision {
	if c == nil || !c.cfg.Enabled {
		return Decision{SubjectHash: subjectHash, Reason: ReasonDisabled}
	}
	if !validSubjectHash(subjectHash) {
		return Decision{Reason: ReasonInvalidHash}
	}
	now := c.cfg.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evaluations++
	if c.evaluations%sweepEvery == 0 {
		c.sweep(now)
	}

	current := c.entries[subjectHash]
	if current != nil {
		c.prune(current, now)
	}
	if riskScore < c.cfg.AuditThreshold {
		if current == nil {
			return Decision{SubjectHash: subjectHash, Reason: ReasonSafe}
		}
		decision := c.decision(subjectHash, current, now)
		decision.Reason = ReasonSafe
		decision.Blocked = false
		if inactive(current, now) {
			delete(c.entries, subjectHash)
		}
		return decision
	}

	if current == nil {
		current = &entry{}
		c.entries[subjectHash] = current
	}
	repeatCount := len(current.hits) + 1
	multiplier := math.Pow(c.cfg.RepeatMultiplier, float64(repeatCount-1))
	if multiplier > c.cfg.MaxMultiplier {
		multiplier = c.cfg.MaxMultiplier
	}
	added := float64(riskScore) * multiplier
	if len(current.hits) >= maxHitsPerSubject {
		// Conservatively combine the two oldest hits at the later timestamp.
		// This bounds adversarial memory use and can only decay more slowly than
		// the exact representation near the oldest hit's expiry.
		current.hits[1].score += current.hits[0].score
		copy(current.hits, current.hits[1:])
		current.hits = current.hits[:len(current.hits)-1]
	}
	current.hits = append(current.hits, hit{at: now, score: added})
	score := c.score(current, now)

	reason := ReasonRisk
	blocked := false
	if current.manualBlocked || score >= c.cfg.ManualBlockScore {
		current.manualBlocked = true
		blocked = true
		reason = ReasonManualBlock
	} else if now.Before(current.cooldownUntil) || score >= c.cfg.CooldownScore {
		blocked = true
		reason = ReasonCooldown
		if !now.Before(current.cooldownUntil) {
			current.cooldownUntil = now.Add(c.cfg.Cooldown)
		}
	}

	return Decision{
		SubjectHash:   subjectHash,
		Blocked:       blocked,
		Reason:        reason,
		Score:         score,
		AddedScore:    added,
		Multiplier:    multiplier,
		CooldownUntil: current.cooldownUntil,
		ManualBlocked: current.manualBlocked,
		RepeatCount:   repeatCount,
	}
}

// Snapshot returns a decayed snapshot and removes expired inactive state.
func (c *Controller) Snapshot(subjectHash string) (State, bool) {
	if c == nil || !c.cfg.Enabled || !validSubjectHash(subjectHash) {
		return State{}, false
	}
	now := c.cfg.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	current, ok := c.entries[subjectHash]
	if !ok {
		return State{}, false
	}
	c.prune(current, now)
	if inactive(current, now) {
		delete(c.entries, subjectHash)
		return State{}, false
	}
	return c.state(subjectHash, current, now), true
}

// Unblock clears manual, cooldown, and rolling history so the next risky event
// starts from a clean state.
func (c *Controller) Unblock(subjectHash string) bool {
	if c == nil || !validSubjectHash(subjectHash) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[subjectHash]; !ok {
		return false
	}
	delete(c.entries, subjectHash)
	return true
}

// Count returns the number of currently allocated subject entries.
func (c *Controller) Count() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.Enabled {
		c.sweep(c.cfg.Now().UTC())
	}
	return len(c.entries)
}

func (c *Controller) sweep(now time.Time) {
	for subjectHash, current := range c.entries {
		c.prune(current, now)
		if inactive(current, now) {
			delete(c.entries, subjectHash)
		}
	}
}

func (c *Controller) decision(subjectHash string, current *entry, now time.Time) Decision {
	return Decision{
		SubjectHash:   subjectHash,
		Score:         c.score(current, now),
		CooldownUntil: current.cooldownUntil,
		ManualBlocked: current.manualBlocked,
		RepeatCount:   len(current.hits),
	}
}

func (c *Controller) state(subjectHash string, current *entry, now time.Time) State {
	return State{
		SubjectHash:   subjectHash,
		Score:         c.score(current, now),
		CooldownUntil: current.cooldownUntil,
		ManualBlocked: current.manualBlocked,
		HitCount:      len(current.hits),
	}
}

func (c *Controller) prune(current *entry, now time.Time) {
	kept := current.hits[:0]
	for _, item := range current.hits {
		if age := now.Sub(item.at); age < c.cfg.Window {
			kept = append(kept, item)
		}
	}
	current.hits = kept
	if !current.cooldownUntil.IsZero() && !now.Before(current.cooldownUntil) {
		current.cooldownUntil = time.Time{}
	}
}

func (c *Controller) score(current *entry, now time.Time) float64 {
	total := 0.0
	window := float64(c.cfg.Window)
	for _, item := range current.hits {
		age := now.Sub(item.at)
		if age < 0 {
			age = 0
		}
		factor := 1 - float64(age)/window
		if factor > 0 {
			total += item.score * factor
		}
	}
	return total
}

func inactive(current *entry, now time.Time) bool {
	return len(current.hits) == 0 && !current.manualBlocked && !now.Before(current.cooldownUntil)
}

func validateConfig(cfg Config) error {
	if cfg.Window <= 0 {
		return errors.New("subject: risk window must be positive")
	}
	if cfg.AuditThreshold <= 0 {
		return errors.New("subject: audit threshold must be positive")
	}
	if !finitePositive(cfg.CooldownScore) {
		return errors.New("subject: cooldown score must be positive and finite")
	}
	if !finitePositive(cfg.ManualBlockScore) || cfg.ManualBlockScore <= cfg.CooldownScore {
		return errors.New("subject: manual block score must be finite and greater than cooldown score")
	}
	if cfg.Cooldown <= 0 {
		return errors.New("subject: cooldown duration must be positive")
	}
	if math.IsNaN(cfg.RepeatMultiplier) || math.IsInf(cfg.RepeatMultiplier, 0) || cfg.RepeatMultiplier < 1 {
		return errors.New("subject: repeat multiplier must be finite and at least 1")
	}
	if math.IsNaN(cfg.MaxMultiplier) || math.IsInf(cfg.MaxMultiplier, 0) || cfg.MaxMultiplier < cfg.RepeatMultiplier {
		return fmt.Errorf("subject: maximum multiplier must be finite and at least %.3g", cfg.RepeatMultiplier)
	}
	return nil
}

func finitePositive(value float64) bool {
	return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func validSubjectHash(value string) bool {
	return validDigest(value, "hmac-sha256:")
}
