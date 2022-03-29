package main

import (
	"fmt"
	"log"
	"sort"
	"time"

	"encoding/json"
	"io/ioutil"
	"net/http"

	"golang.org/x/exp/slices"

	Defend "attack-defend-go/models/defend"
	Adversary "attack-defend-go/models/mitre_attack"
)

// httpGetJson returns a DefendStruct for a given JSON URL (endpoint).
func httpGetJson(endpoint string) Defend.DefendJson {
	client := http.Client{
		Timeout: time.Second * 2, // timeout after 2 seconds
	}

	req, reqErr := http.NewRequest(http.MethodGet, endpoint, nil)
	if reqErr != nil {
		log.Fatal(reqErr)
	}
	res, doErr := client.Do(req)
	if doErr != nil {
		log.Fatal(doErr)
	}
	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	defendData := Defend.DefendJson{}
	jsonErr := json.Unmarshal(body, &defendData)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

	return defendData
}

// Mitigations represents potential defenses for a MITRE ATT&CK technique.
// It allows to add the mitigation name and the number of occurances in
// MITRE ATT&CK techniques.
type Mitigations struct {
	Name  string
	Count int
}

// TopTechniques represents the top techniques for different adversaries.
// It contains a slice of techniques including their unique ID, MITRE tactic,
// and score.
type TopTechniques struct {
	Techniques []struct {
		ID     string
		Tactic string
		Score  int
	}
}

func main() {
	defendEp := "https://d3fend.mitre.org/api/offensive-technique/attack/"
	defendEp = "https://d3fend.mitre.org/api/offensive-technique/attack/T1003.json"

	// Get JSON data from an URL and add it to a struct.
	defendData := httpGetJson(defendEp)

	// Read adverary data from a JSON file.
	content, rfErr := ioutil.ReadFile("./apt32-winnti-turla.json")
	if rfErr != nil {
		log.Fatal(rfErr)
	}

	// Unmarshal the read data and add it to jsonData.
	var jsonData = Adversary.AdversaryJson{}
	if jsonDataErr := json.Unmarshal(content, &jsonData); jsonDataErr != nil {
		log.Fatal(jsonDataErr)
	}

	mitigations := make([]Mitigations, len(defendData.OffToDef.Results.Bindings))
	//var topTechniques = TopTechniques{}

	// Sort jsonData based on their scores.
	sort.Sort(Adversary.AdversaryJson(jsonData))
	fmt.Println(jsonData)
	var alreadyChecked []string
	for i := 0; i < len(jsonData.Techniques); i += 1 {
		if !slices.Contains(alreadyChecked, jsonData.Techniques[i].TechniqueID) {
			//fmt.Printf("ID: %s \t Score: %d\n", jsonData.Techniques[i].TechniqueID,
			//	jsonData.Techniques[i].Score)
			alreadyChecked = append(alreadyChecked, jsonData.Techniques[i].TechniqueID)
		}
	}

	/*
		for j := 0; j < len(defendData.OffToDef.Results.Bindings); j += 1 {
			// only add if name is not already there
			mitigations[j].Name = defendData.OffToDef.Results.Bindings[j].DefTechLabel.Value
		}
	*/
	fmt.Println(mitigations[1])
	// DefTechLabel

	//fmt.Printf("Found %d duplicates.\n", len(alreadyChecked))

	// 1. read json for threat actor or combined threat actors
	// 2. get techniques
	// 3. calc top techniques
	// 4. check at d3fend for techniques (how?)
	// 5. get defenses
	// 6. statistics on defenses (top defense, ...)
	//
	// 1: json read
	// 2: "techniques" field
	// 3: techniques.score
	// 4. GET request: https://d3fend.mitre.org/api/offensive-technique/attack/<techniqueID>.json
	// 5: TODO parsing
	// 6: TODO statistics

}
