package BotProtectionTest

// botProtectionLegitimacyCaveat is the shared caveat appended to every bot protection finding.
const botProtectionLegitimacyCaveat = "A configured commercial protection layer has to be set up by whoever controls the domain, " +
	"which phishing infrastructure rarely bothers with, so the target is more likely legitimate than not. " +
	"Treat this as weak evidence only: free protection tiers are available to attackers too, " +
	"a legitimate site can be compromised while keeping its protection in place, " +
	"and nothing behind the protection layer was actually verified. " +
	"Re-run with the anti-bot detection flag to attempt a real assessment."
