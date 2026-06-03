package config

// normalize.go contains the post-unmarshal normalization helpers
// (normalizePillar1Sources, normalizeStringList, normalizePillar3,
// normalizePillar5) plus EffectiveRedactPlaceholder.
//
// These run inside Load and provide safe defaults / list coercion even when
// users supply partial YAML. EffectiveRedactPlaceholder is the single place
// that chooses the right placeholder across Pillar 3 and Pillar 5.

// normalizePillar1Sources ensures the Pillar1.Sources map and the two v1
// providers ("env", "bitwarden") always exist after unmarshal.
//
// This function guarantees a stable shape for collectors and GetEnvOptions
// (both "env" and "bitwarden" entries always exist after normalization).
func normalizePillar1Sources(cfg *Config) {
	if cfg.Pillar1.Sources == nil {
		cfg.Pillar1.Sources = make(map[string]SourceConfig)
	}

	for _, name := range []string{"env", "bitwarden"} {
		src, ok := cfg.Pillar1.Sources[name]
		if !ok {
			src = SourceConfig{Enabled: name == "env", Options: map[string]any{}}
		}
		if src.Options == nil {
			src.Options = map[string]any{}
		}

		// Normalize common list fields and ensure they are never nil slices.
		for _, key := range []string{"project_roots", "skip_dirs", "ignore_files", "ignore_patterns", "env_file_patterns"} {
			if raw, exists := src.Options[key]; exists && raw != nil {
				normalized := normalizeStringList(raw)
				src.Options[key] = normalized // always set, even if empty
			} else {
				// Guarantee the key exists as a non-nil slice
				src.Options[key] = []string{}
			}
		}

		cfg.Pillar1.Sources[name] = src
	}
}

// normalizeStringList accepts []string, []any, or a single string and returns []string.
func normalizeStringList(v any) []string {
	if v == nil {
		return []string{}
	}
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x == "" {
			return []string{}
		}
		return []string{x}
	default:
		return []string{}
	}
}

// normalizePillar3 ensures Pillar3 has safe defaults for Mode and RedactPlaceholder
// even under partial YAML population. HistoryFiles and HistoryRoots are left
// exactly as provided (nil or populated); the discovery layer treats nil/empty
// as "just $HOME only" (plus explicit extras). After Load()
// these fields may be nil in the returned config.
func normalizePillar3(cfg *Config) {
	if cfg == nil {
		return
	}
	p := cfg.Pillar3
	if !p.Enabled {
		// If disabled, still ensure Mode has a value for any future "status" rendering.
		if p.Mode == "" {
			p.Mode = "delete"
		}
		cfg.Pillar3 = p
		return
	}
	if p.Mode == "" || (p.Mode != "delete" && p.Mode != "redact") {
		p.Mode = "delete"
	}
	if p.RedactPlaceholder == "" {
		p.RedactPlaceholder = "[REDACTED]"
	}
	// HistoryFiles / HistoryRoots are deliberately *not* forced to non-nil here.
	// The discovery logic (and docs) treat nil or empty as "use $HOME only"
	// Callers after Load() may observe nil for these (treated as "HOME only" by discovery).
	// (normalizePillar3 still ensures safe Mode/placeholder.)
	cfg.Pillar3 = p
}

// normalizePillar5 ensures the two independent timeouts (redact + full clear)
// and the redact_placeholder for the Pillar 5 clipboard monitor have sensible values
// after unmarshal of partial user config. Monitor/alert enableds respect explicit
// false from YAML; defaults come from DefaultConfig() before unmarshal.
func normalizePillar5(cfg *Config) {
	if cfg.Pillar5.RedactTimeoutSeconds < 0 {
		cfg.Pillar5.RedactTimeoutSeconds = 0 // 0 disables that tier
	}
	if cfg.Pillar5.FullClearTimeoutSeconds < 0 {
		cfg.Pillar5.FullClearTimeoutSeconds = 0
	}
	if cfg.Pillar5.RedactPlaceholder == "" {
		cfg.Pillar5.RedactPlaceholder = "[REDACTED]"
	}
}

// EffectiveRedactPlaceholder returns the placeholder string to use when redacting
// secrets from clipboard (or history) content. It prefers the Pillar5 value
// (clipboard-specific hygiene preference), falls back to Pillar3, then the
// provided hard default (typically "[REDACTED]").
// This is the single decision point shared by explicit scrub/redact commands
// and the Pillar 5 monitor's auto-redact tier.
func EffectiveRedactPlaceholder(p5, p3, fallback string) string {
	if p5 != "" {
		return p5
	}
	if p3 != "" {
		return p3
	}
	if fallback != "" {
		return fallback
	}
	return "[REDACTED]"
}
