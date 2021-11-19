package transformer

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sensu/sensu-go/types"
)

const (
	AnnotationHelp = "__help__"
	AnnotationType = "__type__"
)

func ToPrometheus(metrics []types.MetricPoint) string {
	pointsByFamily := make(map[string][]types.MetricPoint)
	for _, point := range metrics {
		pointsByFamily[point.Name] = append(pointsByFamily[point.Name], point)
	}
	var out []string
	for family, points := range pointsByFamily {
		familyType := "gauge"
		for _, tag := range points[0].Tags {
			if tag.Name == AnnotationType {
				familyType = tag.Value
				break
			}
		}
		var familyHelp string
		for _, tag := range points[0].Tags {
			if tag.Name == AnnotationHelp {
				familyHelp = tag.Value
				break
			}
		}

		if familyHelp != "" {
			out = append(out, fmt.Sprintf("# HELP %s %s", family, familyHelp))
		}
		out = append(out, fmt.Sprintf("# TYPE %s %s", family, familyType))
		for _, point := range points {
			out = append(out, pointToProm(point))
		}
	}
	return strings.Join(out, "\n")
}

func pointToProm(point types.MetricPoint) string {
	buf := bytes.Buffer{}
	seperator := ""
	for _, tag := range point.Tags {
		if tag.Name == AnnotationHelp || tag.Name == AnnotationType {
			continue
		}
		fmt.Fprintf(&buf, "%s%s=\"%s\"", seperator, tag.Name, tag.Value)
		if seperator == "" {
			seperator = ", "
		}
	}
	var tags string
	if buf.Len() > 0 {
		tags = fmt.Sprintf("{%s}", buf.String())
	}
	return fmt.Sprintf("%s%s %f %d", point.Name, tags, point.Value, point.Timestamp/1e6)
}
