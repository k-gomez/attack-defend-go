package mitre_attack

import "fmt"

func init() {
	fmt.Println("Adversary struct initialized.")
}

// AdversaryJson represents data collected from MITRE ATT&CK navigator exports.
// The input file is JSON and hold different information on adversaries.
// This struct is automatically generated using https://transform.tools/json-to-go
type AdversaryJson struct {
	Name     string `json:"name"`
	Versions struct {
		Attack    string `json:"attack"`
		Navigator string `json:"navigator"`
		Layer     string `json:"layer"`
	} `json:"versions"`
	Domain      string `json:"domain"`
	Description string `json:"description"`
	Filters     struct {
		Platforms []string `json:"platforms"`
	} `json:"filters"`
	Sorting int `json:"sorting"`
	Layout  struct {
		Layout              string `json:"layout"`
		AggregateFunction   string `json:"aggregateFunction"`
		ShowID              bool   `json:"showID"`
		ShowName            bool   `json:"showName"`
		ShowAggregateScores bool   `json:"showAggregateScores"`
		CountUnscored       bool   `json:"countUnscored"`
	} `json:"layout"`
	HideDisabled bool `json:"hideDisabled"`
	Techniques   []struct {
		TechniqueID       string        `json:"techniqueID"`
		Tactic            string        `json:"tactic"`
		Score             int           `json:"score"`
		Color             string        `json:"color"`
		Comment           string        `json:"comment"`
		Enabled           bool          `json:"enabled"`
		Metadata          []interface{} `json:"metadata"`
		Links             []interface{} `json:"links"`
		ShowSubtechniques bool          `json:"showSubtechniques"`
	} `json:"techniques"`
	Gradient struct {
		Colors   []string `json:"colors"`
		MinValue int      `json:"minValue"`
		MaxValue int      `json:"maxValue"`
	} `json:"gradient"`
	LegendItems                   []interface{} `json:"legendItems"`
	Metadata                      []interface{} `json:"metadata"`
	Links                         []interface{} `json:"links"`
	ShowTacticRowBackground       bool          `json:"showTacticRowBackground"`
	TacticRowBackground           string        `json:"tacticRowBackground"`
	SelectTechniquesAcrossTactics bool          `json:"selectTechniquesAcrossTactics"`
	SelectSubtechniquesWithParent bool          `json:"selectSubtechniquesWithParent"`
}

// Len returns the number of techniques in the AdversaryJson struct.
func (a AdversaryJson) Len() int {
	return len(a.Techniques)
}

// Less returns a boolean if the score of technique i is smaller than
// the score of technique j.
func (a AdversaryJson) Less(i, j int) bool {
	return a.Techniques[i].Score > a.Techniques[j].Score
}

// Method to swap technique i and j based on their score.
func (a AdversaryJson) Swap(i, j int) {
	a.Techniques[i], a.Techniques[j] = a.Techniques[j], a.Techniques[i]
}
