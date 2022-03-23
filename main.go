package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

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

func main() {
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

    //fmt.Println(data.Objects[0])    
}
