package transformer_test

import (
	"testing"

	"github.com/sensu/dns-check/internal/transformer"
	v2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/types"
)

func TestToPrometheus(t *testing.T) {
	points := []types.MetricPoint{
		{
			Name:  "foo",
			Value: 11,
			Tags: []*v2.MetricTag{
				{
					Name:  transformer.AnnotationHelp,
					Value: "simple test metric",
				},
				{
					Name:  transformer.AnnotationType,
					Value: "counter",
				},
				{
					Name:  "custom-tag-1",
					Value: "X",
				},
			},
		}, {
			Name:  "foo",
			Value: 22,
			Tags: []*v2.MetricTag{
				{
					Name:  "custom-tag-1",
					Value: "Y",
				},
			},
		}, {
			Name:  "foo",
			Value: 33,
			Tags: []*v2.MetricTag{
				{
					Name:  "custom-tag-1",
					Value: "Z",
				},
			},
		},
	}

	actual := transformer.ToPrometheus(points)
	expected := `# HELP foo simple test metric
# TYPE foo counter
foo{custom-tag-1="X"} 11.000000 0
foo{custom-tag-1="Y"} 22.000000 0
foo{custom-tag-1="Z"} 33.000000 0`

	if actual != expected {
		t.Errorf("expected prometheus output does not match actual. Expected:\n%s\nGot:\n%s", expected, actual)
	}
}
