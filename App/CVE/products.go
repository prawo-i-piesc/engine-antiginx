package CVE

// Product names a piece of software the way the CPE dictionary does, which is how NVD records
// which versions a CVE affects.
type Product struct {
	Vendor  string
	Product string
}

// cpeProducts maps the technology names the engine detects to their CPE vendor and product.
// Every entry was checked against NVD by querying a release with a known CVE; a technology
// without a verified entry is looked up by keyword only, which cannot tell which of the CVEs
// found apply to a given release.
var cpeProducts = map[string]Product{
	"Apache":        {Vendor: "apache", Product: "http_server"},                      // 2.4.49 → CVE-2021-41773
	"Nginx":         {Vendor: "f5", Product: "nginx"},                                // 1.18.0 → CVE-2021-23017
	"Microsoft IIS": {Vendor: "microsoft", Product: "internet_information_services"}, // 7.5 → CVE-2010-2730
	"PHP":           {Vendor: "php", Product: "php"},                                 // 7.4.3 → 30 CVEs
	"Gunicorn":      {Vendor: "gunicorn", Product: "gunicorn"},                       // 19.4.5 → CVE-2018-1000164
	"Uvicorn":       {Vendor: "encode", Product: "uvicorn"},                          // 0.11.6 → CVE-2020-7695
	"WordPress":     {Vendor: "wordpress", Product: "wordpress"},                     // 5.0 → CVE-2018-20147
	"Drupal":        {Vendor: "drupal", Product: "drupal"},                           // 7.0 → CVE-2011-2687
}

// ProductFor returns the CPE product of a detected technology, if it has a verified one.
func ProductFor(technology string) (Product, bool) {
	product, known := cpeProducts[technology]
	return product, known
}
