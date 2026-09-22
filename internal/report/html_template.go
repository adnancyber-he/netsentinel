package report

import "html/template"

// htmlTmpl is a fully self-contained dark-themed report.
// No external CSS or JS is required.
var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"humanBytes": humanBytes,
	"humanRate":  humanRate,
	"fmtFloat":   func(f float64) string { return fmtFloat(f) },
}).Parse(htmlTemplateSrc))

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmtFloat(float64(b)) + " B"
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmtFloat(float64(b)/float64(div)) + " " + units[exp]
}

func humanRate(bps float64) string {
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	i := 0
	for bps >= 1000 && i < len(units)-1 {
		bps /= 1000
		i++
	}
	return fmtFloat(bps) + " " + units[i]
}

func fmtFloat(f float64) string {
	return template.HTMLEscapeString(trimFloat(f))
}

func trimFloat(f float64) string {
	// Avoid importing strconv in the template file by using fmt via a helper
	return formatFloat(f, 2)
}