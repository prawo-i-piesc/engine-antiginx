package CVE

// CVSS qualitative severity ratings, spelled as NVD reports them. A CVE that no one has scored
// yet has no rating at all, which is not the same as Low.
const (
	SeverityNone     = "NONE"     // CVSS 3.x/4.0 score 0.0
	SeverityLow      = "LOW"      // 0.1–3.9 (CVSS 2.0: 0.0–3.9)
	SeverityMedium   = "MEDIUM"   // 4.0–6.9
	SeverityHigh     = "HIGH"     // 7.0–8.9 (CVSS 2.0: 7.0–10.0)
	SeverityCritical = "CRITICAL" // 9.0–10.0, CVSS 3.x/4.0 only
	SeverityUnscored = ""         // No CVSS metric published yet
)

// severityRank orders the ratings so the most severe of several can be picked.
var severityRank = map[string]int{
	SeverityUnscored: 0,
	SeverityNone:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

// MoreSevere reports whether rating a is more severe than rating b.
func MoreSevere(a string, b string) bool {
	return severityRank[a] > severityRank[b]
}

// SeverityFromScore converts a CVSS base score into the qualitative rating defined by the CVSS
// version it was computed under: the FIRST CVSS 3.x and 4.0 scale, or the three-band scale NVD
// uses for CVSS 2.0, which has no Critical — a 10.0 under 2.0 is High.
func SeverityFromScore(version string, score float64) string {
	if version == "2.0" {
		switch {
		case score >= 7.0:
			return SeverityHigh
		case score >= 4.0:
			return SeverityMedium
		default:
			return SeverityLow
		}
	}
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// nvdMetric is one CVSS scoring of a vulnerability, by NVD itself ("Primary") or by the CVE
// Numbering Authority that published it ("Secondary").
type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// nvdMetrics are a vulnerability's scorings, one list per CVSS version.
type nvdMetrics struct {
	CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
	CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
}

// selectMetric picks the scoring that stands for a vulnerability: NVD's own assessment in the
// newest CVSS version NVD scored it under, or, while NVD has not scored it, the publishing
// CNA's in the newest version available. NVD lists a CNA's scoring before its own about as
// often as after it, so the order of the list says nothing.
func (m nvdMetrics) selectMetric() (nvdMetric, bool) {
	newestFirst := []struct {
		version  string
		scorings []nvdMetric
	}{{"4.0", m.CVSSMetricV40}, {"3.1", m.CVSSMetricV31}, {"3.0", m.CVSSMetricV30}, {"2.0", m.CVSSMetricV2}}

	// The list a scoring sits in names its CVSS version, should cvssData leave it out
	labelled := func(scoring nvdMetric, version string) nvdMetric {
		if scoring.CVSSData.Version == "" {
			scoring.CVSSData.Version = version
		}
		return scoring
	}

	for _, list := range newestFirst {
		for _, scoring := range list.scorings {
			if scoring.Type == "Primary" {
				return labelled(scoring, list.version), true
			}
		}
	}
	for _, list := range newestFirst {
		if len(list.scorings) > 0 {
			return labelled(list.scorings[0], list.version), true
		}
	}
	return nvdMetric{}, false
}
