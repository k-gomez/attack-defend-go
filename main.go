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
func httpGetJson(endpoint string) *Defend.DefendJson {
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
		fmt.Errorf("Unmarshal error. Error message: \n%s", jsonErr)
		return nil
	}

	return &defendData
}

// Mitigation represents potential defenses for a MITRE ATT&CK technique.
// It allows to add the mitigation name and the number of occurances in
// MITRE ATT&CK techniques.
type Mitigation struct {
	Key   string
	Value int
}

type MitigationList []Mitigation

func (p MitigationList) Len() int           { return len(p) }
func (p MitigationList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p MitigationList) Less(i, j int) bool { return p[i].Value < p[j].Value }

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
	content, rfErr := ioutil.ReadFile("./apt41-fin6-apt3-apt32-winnti.json")
	if rfErr != nil {
		log.Fatal(rfErr)
	}

	// Unmarshal the read data and add it to jsonData.
	var adversaryJson = Adversary.AdversaryJson{}
	if adversaryJsonErr := json.Unmarshal(content, &adversaryJson); adversaryJsonErr != nil {
		log.Fatal(adversaryJsonErr)
	}

	// Sort jsonData based on their scores.
	sort.Sort(Adversary.AdversaryJson(adversaryJson))
	fmt.Printf("Collected %d techniques from file.\n",
		len(adversaryJson.Techniques))

	// Get unique techniques.
	var uniqueTechniques []string
	for i := 0; i < len(adversaryJson.Techniques); i += 1 {
		if !slices.Contains(uniqueTechniques, adversaryJson.Techniques[i].TechniqueID) {
			uniqueTechniques = append(uniqueTechniques,
				adversaryJson.Techniques[i].TechniqueID)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(uniqueTechniques)))
	fmt.Printf("Got %d unique techniques.\n", len(uniqueTechniques))

	defendEp := "https://d3fend.mitre.org/api/offensive-technique/attack/"
	var mitigations = make(map[string]int)

	// Go over all unique techniques and
	// collect JSON from D3FEND's endpoint.
	for j := 0; j < len(uniqueTechniques); j += 1 {
		techniqueLink := defendEp + uniqueTechniques[j] + ".json"

		defendData := httpGetJson(techniqueLink)

		if defendData != nil {
			for jj := 0; jj < len(defendData.OffToDef.Results.Bindings); jj += 1 {
				mitigations[defendData.OffToDef.Results.Bindings[jj].
					DefTechLabel.Value] += 1
			}
		}
	}

	m := make(MitigationList, len(mitigations))

	i := 0
	for k, v := range mitigations {
		m[i] = Mitigation{k, v}
		i++
	}
	sort.Sort(m)
	//fmt.Println(m)

	sum := 0
	for mitig := range m {
		fmt.Println(m[mitig])
		sum += m[mitig].Value
	}
	fmt.Printf("Sum: %d", sum)
}
