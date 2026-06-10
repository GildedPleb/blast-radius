package config

// DefaultSkipDirs are directories that should almost never contain legitimate
// secrets. These are safe, universal defaults that apply to virtually every
// project. They are not user-specific.
var DefaultSkipDirs = []string{
	"node_modules",
	".git",
	"vendor",
	"dist",
	"build",
	".next",
	"target",
	"out",
	".cache",
	"coverage",
	".venv",
	"__pycache__",
}

// DefaultIgnoreFiles are filenames that should be ignored by Pillar 1
// discovery even if they would otherwise match an env file pattern.
var DefaultIgnoreFiles = []string{
	".gitignore",
	".blastradiusignore",
}

// DefaultIgnorePatterns are well-known non-secret / high-noise environment
// variable names and patterns. These are safe to ship as defaults because
// they are not user-specific secrets.
var DefaultIgnorePatterns = []string{
	"PATH", "HOME", "PWD", "USER", "SHELL", "TERM",
	"LANG", "LC_*", "EDITOR", "VISUAL", "PAGER",
	"COLORTERM", "DISPLAY", "XDG_*",
	"DBUS_*", "DESKTOP_SESSION", "GNOME_*", "KDE_*",
	"SSH_*", "GPG_*", "LESS*", "MORE",
	"PS1", "PS2", "PROMPT*", "HIST*", "HISTSIZE",
	"LOG_*", "*_NONSECRET", "BUILD_*", "CI_*",
	"NODE_ENV", "DEBUG", "TEST_*",
}

// DefaultPillar2Dirs are the default high-risk surfaces scanned by Pillar 2
// when it is first enabled. These are common locations where users might
// accidentally leave secrets (downloads, documents, desktop).
var DefaultPillar2Dirs = []Pillar2Dir{
	{Path: "~/Downloads", Files: []string{"**/*"}},
	{Path: "~/Documents", Files: []string{"**/*"}},
	{Path: "~/Desktop", Files: []string{"**/*"}},
}
