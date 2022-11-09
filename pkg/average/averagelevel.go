package average

import (
	"strings"
)

func GetAverageLevel(advice []string) (averageLevel int) {
	var level int
	for _, advice := range advice {
		level += GetLevel(advice)
	}
	averageLevel = level / len(advice)
	return averageLevel
}

func GetLevel(advice string) (level int) {
	if strings.Contains(advice, "LEVEL 0") {
		level = 0
	}
	if strings.Contains(advice, "LEVEL 1") {
		level = 1
	}
	if strings.Contains(advice, "LEVEL 2") {
		level = 2
	}
	return level
}
