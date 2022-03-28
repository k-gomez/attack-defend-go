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

	AdversaryJson "github.com/k-gomez/attack-defend-go/models"
)

type DefendStruct struct {
	OffToDef struct {
		Head struct {
			Vars []string `json:"vars"`
		} `json:"head"`
		Results struct {
			Bindings []struct {
				Sc struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"sc"`
				OffArtifactLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_artifact_label"`
				OffArtifactRelLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_artifact_rel_label"`
				OffTechLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_tech_label"`
				OffTacticRelLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_tactic_rel_label"`
				OffTacticLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_tactic_label"`
				OffArtifact struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_artifact"`
				OffArtifactRel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_artifact_rel"`
				OffTech struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_tech"`
				OffTechID struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_tech_id"`
				OffTacticRel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_tactic_rel"`
				OffTactic struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"off_tactic"`
				DefTacticLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_tactic_label,omitempty"`
				DefTacticRelLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_tactic_rel_label,omitempty"`
				DefTechParentIsToplevel struct {
					Datatype string `json:"datatype"`
					Type     string `json:"type"`
					Value    string `json:"value"`
				} `json:"def_tech_parent_is_toplevel,omitempty"`
				DefTechParentLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_tech_parent_label,omitempty"`
				DefTechLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_tech_label,omitempty"`
				DefArtifactRelLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_artifact_rel_label,omitempty"`
				DefArtifactLabel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_artifact_label,omitempty"`
				DefTactic struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_tactic,omitempty"`
				DefTacticRel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_tactic_rel,omitempty"`
				DefTech struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_tech,omitempty"`
				DefArtifactRel struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_artifact_rel,omitempty"`
				DefArtifact struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"def_artifact,omitempty"`
			} `json:"bindings"`
		} `json:"results"`
	} `json:"off_to_def"`
	Description struct {
		Context struct {
			D3F      string `json:"d3f"`
			Rdfs     string `json:"rdfs"`
			Skos     string `json:"skos"`
			Owl      string `json:"owl"`
			Children struct {
				ID        string `json:"@id"`
				Type      string `json:"@type"`
				Container string `json:"@container"`
			} `json:"children"`
		} `json:"@context"`
		Graph []struct {
			ID          string   `json:"@id"`
			Type        []string `json:"@type"`
			D3FAccesses struct {
				ID string `json:"@id"`
			} `json:"d3f:accesses"`
			D3FAttackID    string `json:"d3f:attack-id"`
			RdfsLabel      string `json:"rdfs:label"`
			RdfsSubClassOf struct {
				ID string `json:"@id"`
			} `json:"rdfs:subClassOf"`
		} `json:"@graph"`
	} `json:"description"`
	Subtechniques struct {
		Context struct {
			D3F      string `json:"d3f"`
			Rdfs     string `json:"rdfs"`
			Skos     string `json:"skos"`
			Owl      string `json:"owl"`
			Children struct {
				ID        string `json:"@id"`
				Type      string `json:"@type"`
				Container string `json:"@container"`
			} `json:"children"`
		} `json:"@context"`
		Graph []struct {
			ID              string `json:"@id"`
			D3FD3FAttackID  string `json:"d3f:d3f:attack-id,omitempty"`
			D3FTopLevel     string `json:"d3f:top-level,omitempty"`
			RdfsHasSubClass []struct {
				ID string `json:"@id"`
			} `json:"rdfs:hasSubClass,omitempty"`
			RdfsLabel      string `json:"rdfs:label"`
			D3FAttackID    string `json:"d3f:attack-id,omitempty"`
			RdfsSubClassOf struct {
				ID string `json:"@id"`
			} `json:"rdfs:subClassOf,omitempty"`
		} `json:"@graph"`
	} `json:"subtechniques"`
}

// httpGetJson returns a DefendStruct for a given JSON URL (endpoint).
func httpGetJson(endpoint string) DefendStruct {
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

	defendData := DefendStruct{}
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
	var jsonData = AdversaryJson.Adversary{}
	if jsonDataErr := json.Unmarshal(content, &jsonData); jsonDataErr != nil {
		log.Fatal(jsonDataErr)
	}

	mitigations := make([]Mitigations, len(defendData.OffToDef.Results.Bindings))
	//var topTechniques = TopTechniques{}

	// Sort jsonData based on their scores.
	sort.Sort(AdversaryJson.Adversary(jsonData))
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
