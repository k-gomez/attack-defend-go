package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	//"net/http"
	"golang.org/x/exp/slices"
	"time"
)

// rename tool to Ade!

// automatically generated using https://transform.tools/json-to-go
// source json:
// https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
type EnterpriseAttack struct {
	Type    string `json:"type"`
	Objects []struct {
		Type                      string    `json:"type"`
		Modified                  time.Time `json:"modified,omitempty"`
		Name                      string    `json:"name,omitempty"`
		XMitreDataSources         []string  `json:"x_mitre_data_sources,omitempty"`
		XMitreVersion             string    `json:"x_mitre_version,omitempty"`
		Created                   time.Time `json:"created"`
		XMitrePermissionsRequired []string  `json:"x_mitre_permissions_required,omitempty"`
		XMitrePlatforms           []string  `json:"x_mitre_platforms,omitempty"`
		XMitreIsSubtechnique      bool      `json:"x_mitre_is_subtechnique,omitempty"`
		ID                        string    `json:"id"`
		Description               string    `json:"description,omitempty"`
		ObjectMarkingRefs         []string  `json:"object_marking_refs,omitempty"`
		KillChainPhases           []struct {
			KillChainName string `json:"kill_chain_name"`
			PhaseName     string `json:"phase_name"`
		} `json:"kill_chain_phases,omitempty"`
		XMitreDetection    string `json:"x_mitre_detection,omitempty"`
		CreatedByRef       string `json:"created_by_ref,omitempty"`
		ExternalReferences []struct {
			SourceName  string `json:"source_name"`
			ExternalID  string `json:"external_id,omitempty"`
			URL         string `json:"url"`
			Description string `json:"description,omitempty"`
		} `json:"external_references,omitempty"`
		XMitreContributors         []string `json:"x_mitre_contributors,omitempty"`
		XMitreSystemRequirements   []string `json:"x_mitre_system_requirements,omitempty"`
		XMitreDefenseBypassed      []string `json:"x_mitre_defense_bypassed,omitempty"`
		XMitreEffectivePermissions []string `json:"x_mitre_effective_permissions,omitempty"`
		Revoked                    bool     `json:"revoked,omitempty"`
		XMitreImpactType           []string `json:"x_mitre_impact_type,omitempty"`
		XMitreNetworkRequirements  bool     `json:"x_mitre_network_requirements,omitempty"`
		XMitreRemoteSupport        bool     `json:"x_mitre_remote_support,omitempty"`
		XMitreDeprecated           bool     `json:"x_mitre_deprecated,omitempty"`
		TargetRef                  string   `json:"target_ref,omitempty"`
		SourceRef                  string   `json:"source_ref,omitempty"`
		RelationshipType           string   `json:"relationship_type,omitempty"`
		XMitreOldAttackID          string   `json:"x_mitre_old_attack_id,omitempty"`
		IdentityClass              string   `json:"identity_class,omitempty"`
		Aliases                    []string `json:"aliases,omitempty"`
		XMitreAliases              []string `json:"x_mitre_aliases,omitempty"`
		Labels                     []string `json:"labels,omitempty"`
		XMitreShortname            string   `json:"x_mitre_shortname,omitempty"`
		TacticRefs                 []string `json:"tactic_refs,omitempty"`
		XMitreCollectionLayers     []string `json:"x_mitre_collection_layers,omitempty"`
		XMitreDataSourceRef        string   `json:"x_mitre_data_source_ref,omitempty"`
		Definition                 struct {
			Statement string `json:"statement"`
		} `json:"definition,omitempty"`
		DefinitionType string `json:"definition_type,omitempty"`
	} `json:"objects"`
	ID          string `json:"id"`
	SpecVersion string `json:"spec_version"`
}

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

type TopTechniques struct {
	Technique []struct {
		TechniqueID string
		Tactic      string
		Score       int
	}
}

func (aJ *AdversaryJson) GetTopTechniques() TopTechniques {
	var topTechniques TopTechniques

	return topTechniques
}

func main() {
	/*
	   endpoint := "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

	   client := http.Client {
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

	   stix, readErr := ioutil.ReadAll(res.Body)
	   if readErr != nil {
	       log.Fatal(readErr)
	   }

	   data := EnterpriseAttack {}
	   jsonErr := json.Unmarshal(stix, &data)
	   if jsonErr != nil {
	       log.Fatal(jsonErr)
	   }
	*/

	content, rfErr := ioutil.ReadFile("./apt32-winnti-turla.json")
	if rfErr != nil {
		log.Fatal(rfErr)
	}

	jsonData := AdversaryJson{}
	jsonDataErr := json.Unmarshal(content, &jsonData)
	if jsonDataErr != nil {
		log.Fatal(jsonDataErr)
	}

	var alreadyChecked []string
	for i := 0; i < len(jsonData.Techniques); i += 1 {
		if !slices.Contains(alreadyChecked, jsonData.Techniques[i].TechniqueID) {
			fmt.Printf("ID: %s \t Score: %d\n", jsonData.Techniques[i].TechniqueID,
				jsonData.Techniques[i].Score)
			alreadyChecked = append(alreadyChecked, jsonData.Techniques[i].TechniqueID)
		}
	}
	fmt.Printf("Found %d duplicates.\n", len(alreadyChecked))

	// there is no reason to do it like this
	// I need the tactics navigator export (prefered in json)
	// here we have tactics from mitre and our threat intelligence
	//
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
