package handlers

import "fmt"

type DuplicatesHandler struct{}

func (DuplicatesHandler) Name() string { return "DUPLICATES" }

func init() { Register(DuplicatesHandler{}) }

func (DuplicatesHandler) Handle(_ string, d DaemonContext) (any, error) {
	dups := d.FindDuplicates()
	serializable := make([]map[string]any, 0, len(dups))
	for hash, projects := range dups {
		projStrs := make([]string, len(projects))
		for i, p := range projects {
			projStrs[i] = d.GetProjectDisplayName(p)
		}
		serializable = append(serializable, map[string]any{
			"hash":     fmt.Sprintf("%x", hash),
			"projects": projStrs,
			"count":    len(projects),
		})
	}
	return map[string]any{
		"status":     "ok",
		"duplicates": serializable,
		"total":      len(dups),
	}, nil
}
