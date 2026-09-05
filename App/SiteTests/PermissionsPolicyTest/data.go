package PermissionsPolicyTest

// The browser features this test grades a policy against, split by what an unrestricted
// grant actually costs the visitor.

// dangerousFeatures reach hardware or location.
var dangerousFeatures = []string{
	"camera", "microphone", "geolocation", "payment", "usb", "bluetooth",
	"serial", "hid", "midi", "notifications", "persistent-storage", "clipboard-read",
}

// suspiciousFeatures do not reach hardware, but they are the ones tracking and fingerprinting
// scripts reach for, so a policy that leaves them open says something about how much the site
// restricts what it embeds.
var suspiciousFeatures = []string{
	"fullscreen", "autoplay", "screen-wake-lock", "picture-in-picture",
}
