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
		log.Fatalf("Request error. Error message: \n%s", reqErr)
	}
	res, doErr := client.Do(req)
	if doErr != nil {
		log.Fatalf("Do error. Error message: \n%s", doErr)
	}
	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatalf("ReadAll error. Error message: \n%s", readErr)
	}

	defendData := Defend.DefendJson{}
	jsonErr := json.Unmarshal(body, &defendData)
	if jsonErr != nil {
		//log.Fatalf("Unmarshal error. Error message: \n%s", jsonErr)
		fmt.Printf("Unmarshal error. Error message: \n%s", jsonErr)
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

	// Sort jsonData based on their scores.
	sort.Sort(Adversary.AdversaryJson(jsonData))
	var alreadyChecked []string
	for i := 0; i < len(jsonData.Techniques); i += 1 {
		if !slices.Contains(alreadyChecked, jsonData.Techniques[i].TechniqueID) {
			//fmt.Printf("ID: %s \t Score: %d\n", jsonData.Techniques[i].TechniqueID,
			//	jsonData.Techniques[i].Score)
			alreadyChecked = append(alreadyChecked, jsonData.Techniques[i].TechniqueID)
		} // alreadyChecked now contains the uniuqe techniques in the JSON
	}
	sort.Sort(sort.Reverse(sort.StringSlice(alreadyChecked)))
	//fmt.Println(alreadyChecked)

	defendEp := "https://d3fend.mitre.org/api/offensive-technique/attack/"
	var mitigations []string

	for j := 0; j < len(alreadyChecked); j += 1 {
		techniqueLink := defendEp + alreadyChecked[j] + ".json"
		//fmt.Println(techniqueLink)

		defendData := httpGetJson(techniqueLink)

		for jj := 0; jj < len(defendData.OffToDef.Results.Bindings); jj += 1 {
			//fmt.Println(defendData.OffToDef.Results.Bindings[jj].DefTechLabel.Value)
			mitigations = append(mitigations,
				defendData.OffToDef.Results.Bindings[jj].DefTechLabel.Value)
		}
	}
	fmt.Println(mitigations)

	//mitigations := make([]Mitigations, len(defendData.OffToDef.Results.Bindings))

	// testing
	//defendEp = "https://d3fend.mitre.org/api/offensive-technique/attack/T1003.json"

	// Get JSON data from an URL and add it to a struct.

	//var topTechniques = TopTechniques{}

	/*
		for j := 0; j < len(defendData.OffToDef.Results.Bindings); j += 1 {
			// only add if name is not already there
			mitigations[j].Name = defendData.OffToDef.Results.Bindings[j].DefTechLabel.Value
		}
	*/
	//fmt.Println(mitigations[1])
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
