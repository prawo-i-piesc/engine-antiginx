# DNS and Domain Registration Analysis

Answers the questions the domain registration system and the DNS can answer about a target
before a single byte of its page is trusted: where the domain was registered, when, how
long it has been held by its current holder, what it resolves to and who operates those
addresses.

The test exists because a phishing site is usually young infrastructure wearing an old
brand. Its page can be a pixel-perfect copy of the original, but the domain behind it was
registered last week, is held by nobody identifiable, is served by free infrastructure,
publishes no mail policy because nobody ever intended to receive mail on it, and answers
from an address in somebody's consumer broadband pool. None of that is visible in the HTML,
and all of it is visible in the DNS.

|  |  |
|---|---|
| **Test ID** | `dns-reputation` |
| **Phase** | PreResponse — runs from the target URL alone, in parallel with the page fetch, so it still reports when the target is unreachable or blocked |
| **Category** | Phishing |

```bash
go run ./App/main.go test --target example.com --tests dns-reputation
```

## What it checks

**Registration**, over RDAP — the protocol that replaced WHOIS:

- Registrar and its country, and the registrant's country where the registry still publishes it
- Registration date and the domain's age
- The current registration period and when it expires
- EPP status codes, including the ones that mean a registry has taken the domain out of service
- **How long the domain has been held by its current holder**, derived from the registry's
  transfer event — which separates an aged domain from an aged domain that changed hands last month

**Resolution**, over ordinary DNS:

- Address records, and the canonical name the hostname is aliased to
- The nameservers serving the zone
- Whether the zone answers for names nobody configured (a wildcard)
- Whether the hostname was handed out by a tunnelling service, a dynamic DNS provider or a
  free hosting platform rather than being a domain somebody registered

**Networks**, for every resolved address:

- The organisation the address block is allocated to, its country and its allocation type
- Whether the block publishes an abuse contact
- The address's reverse name, and whether it follows the naming convention access providers
  use for consumer pools

**Mail policy**, read as evidence of intent rather than of mail security:

- SPF, DMARC and mail exchangers. A domain its owner actually uses accumulates a mail
  configuration; a domain registered to be clicked once has none.

## How it works

Three sources are queried, two of them concurrently because neither feeds the other.

1. **Registration.** The hostname is reduced to the domain somebody registered. That
   boundary cannot always be derived locally — an unfamiliar two-label suffix would
   otherwise be queried as the suffix itself — so up to two candidates are tried, and a
   "not found" answer is an instruction to try the longer one rather than a failure.
   The query goes to a bootstrap service that redirects it to whichever registry is
   authoritative.
2. **Zone.** Seven DNS queries are issued at once under a single deadline: addresses, the
   canonical name, nameservers, mail exchangers, the zone's TXT records for SPF, `_dmarc`
   for DMARC, and a wildcard probe — a random label nobody ever configured, which a zone
   that resolves every possible name still answers.
3. **Addresses.** Only then, because it needs what resolution produced. Up to four
   addresses are inspected in parallel — a large CDN returns a different subset of a very
   large pool on every query, so inspecting all of them would spend the time budget
   rediscovering the same operator. Each gets an RDAP allocation lookup and a reverse
   lookup.

Every lookup is bounded by its own timeout and every failure is recorded in the metadata
rather than propagated. A target scanned from a machine with no outbound access still gets
its DNS analysis, only with lower confidence. Nothing in this test panics.

## How the verdict is reached

Each observation becomes an indicator carrying its own severity. The reported level is the
highest of them, **raised by one when at least two independent indicators reach Medium** —
because the value of these signals is cumulative. A young domain is common. A young domain
on free anonymous infrastructure with no mail policy and an address in consumer space is a
phishing page.

| Level | When |
|---|---|
| **None** | Registration and DNS look like those of an established, used domain |
| **Info** | Only informational observations, or registration data was unavailable |
| **Low** | Weak indicators — a young domain, a missing mail policy, a free hosting platform |
| **Medium** | Free or anonymous infrastructure, a wildcard zone, a recent change of holder |
| **High** | Very recent registration, a suspended registration, an ephemeral tunnel hostname, or an address that is non-routable or in consumer space |
| **Critical** | A High indicator coinciding with further independent Medium evidence — the shape of a complete phishing deployment rather than one anomaly |

Confidence follows how much evidence could be gathered: 100% when both sources answered and
found nothing, 90% when the verdict is derived from what they said, 75% when one source was
unreachable, 55% when neither was.

## What it reports

| Section | Holds |
|---|---|
| `Host`, `RegistrableDomain` | What was analysed, and the domain the registry queries were made for |
| `Registration` | `Registrar`, `RegistrarCountry`, `RegistrantCountry`, `Registered`, `Expires`, `LastChanged`, `Transferred`, `Statuses`, `Nameservers`, `DNSSECSigned`, and the derived `AgeDays`, `TenureDays`, `LastChangedDaysAgo`, `DaysUntilExpiry`, `RegistrationPeriodDays` |
| `Resolution` | `IPv4Addresses`, `IPv6Addresses`, `CanonicalName`, `Nameservers`, `MailExchangers`, `WildcardDNS`, `HostingService`, `HostingServiceKind` |
| `MailAuthentication` | `SPFRecord`, `SPFAllowsAnySender`, `DMARCRecord`, `DMARCPolicy`, `MailExchangersPresent` |
| `Networks[]` | Per address: `Public`, `Scope`, `Network`, `Organization`, `Country`, `AllocationType`, `AbusePublished`, `ReverseNames`, `DynamicReverseName` |
| `Indicators[]` | Every observation, as `Code`, `Detail` and `Severity`, most severe first |

Day counters hold `-1` when the date they derive from was not published — so an unresolved
lookup can never be read as "registered today".

## Files

| File | Holds |
|---|---|
| `core.go` | `New()`, the indicator evaluation — the whole judgement — and the collector wiring |
| `config.go` | Identity, timeouts, address budget, age and tenure thresholds, confidence levels, the RDAP entry point |
| `data.go` | Public suffixes, managed platform suffixes, free DNS providers, access-network name markers, abuse-prone namespaces, reserved address ranges |
| `modules/collector.go` | The metadata types and the acquisition: RDAP and DNS |
| `modules/rdap.go` | RDAP wire format decoding, including the jCard contact encoding |
| `modules/naming.go` | Classifying hostnames, nameservers and addresses against the datasets |

## Notes

**No paid feeds.** Every conclusion comes from RDAP and ordinary DNS, both free to use at
any volume and needing no API key. The cost is that there is never an external operator's
verdict to lean on: the classification is always this engine's own reading of the evidence.

**Platform hostnames are called out.** When the hostname belongs to a shared platform, the
registration record describes the platform operator rather than whoever published the page.
The finding says so explicitly, so the platform's domain age is never read as the site's.

**Fast-flux by TTL is not detected.** Go's standard resolver does not expose record TTLs,
so the classic low-TTL signal is unavailable. The test approximates it by counting distinct
network operators among the resolved addresses. A real TTL check would need a DNS client
library — the first external dependency in this project.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ANTIGINX_RDAP_URL` | `https://rdap.org` | RDAP entry point. Point it at an internal mirror or a registry endpoint. |

---

The framework this test plugs into, and the conventions every test folder follows, are
documented in [`App/SiteTests/README.md`](../README.md).
