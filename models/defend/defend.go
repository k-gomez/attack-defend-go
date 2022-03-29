package defend

import "fmt"

func init() {
	fmt.Println("Defend struct initialized.")
}

type DefendJson struct {
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
