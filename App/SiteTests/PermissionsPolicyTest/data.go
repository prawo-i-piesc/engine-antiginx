package PermissionsPolicyTest

// The browser features this test grades a policy against, split by what an unrestricted
// grant actually costs the visitor. Names are matched exactly, as the policy-controlled
// feature registry spells them.

// dangerousFeatures reach hardware, location, the screen, credentials or locally stored data.
var dangerousFeatures = []string{
	// Capture devices and location
	"camera", "microphone", "geolocation", "display-capture", "captured-surface-control",
	"speaker-selection",

	// Hardware and device interfaces
	"usb", "bluetooth", "serial", "hid", "midi", "gamepad", "direct-sockets",
	"xr-spatial-tracking",

	// Motion and environment sensors
	"accelerometer", "gyroscope", "magnetometer", "ambient-light-sensor",

	// Payments and credentials
	"payment", "otp-credentials", "publickey-credentials-get", "publickey-credentials-create",
	"identity-credentials-get",

	// Clipboard, storage and local data
	"clipboard-read", "clipboard-write", "persistent-storage", "storage-access", "local-fonts",

	// User presence and the wider desktop
	"notifications", "idle-detection", "window-management",
}

// suspiciousFeatures do not reach hardware, but they are the ones tracking and fingerprinting
// scripts reach for, so a policy that leaves them open says something about how much the site
// restricts what it embeds.
var suspiciousFeatures = []string{
	// Media and presentation
	"fullscreen", "autoplay", "screen-wake-lock", "picture-in-picture", "encrypted-media",

	// Advertising and cross-site measurement
	"browsing-topics", "interest-cohort", "attribution-reporting", "join-ad-interest-group",
	"run-ad-auction", "private-aggregation", "shared-storage", "shared-storage-select-url",
	"private-state-token-issuance", "private-state-token-redemption",

	// High-entropy client hints and other fingerprinting surfaces
	"ch-ua-arch", "ch-ua-bitness", "ch-ua-full-version", "ch-ua-full-version-list",
	"ch-ua-model", "ch-ua-platform-version", "ch-ua-wow64", "ch-device-memory",
	"compute-pressure",

	// Legacy behaviour a policy is expected to switch off
	"document-domain", "sync-xhr",
}
