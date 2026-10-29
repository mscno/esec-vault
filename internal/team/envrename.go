package team

import "fmt"

// EnvRenameBody changes a name without rotating its key or changing readers.
type EnvRenameBody struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// CurrentEnv resolves historical grant names through verified rename links.
func (s *State) CurrentEnv(name string) string {
	if n := s.EnvRenames[name]; n != "" {
		return n
	}
	return name
}

func (s *State) renameEnv(l Link) error {
	var b EnvRenameBody
	if err := decodeBody(l, &b); err != nil {
		return err
	}
	if err := ValidEnv(b.New); err != nil {
		return err
	}
	e, ok := s.Envs[b.Old]
	if !ok {
		return fmt.Errorf("unknown environment %s", b.Old)
	}
	if _, ok := s.Envs[b.New]; ok || s.EnvRenames[b.New] != "" {
		return fmt.Errorf("environment %s exists or is retired", b.New)
	}
	delete(s.Envs, b.Old)
	e.Name = b.New
	s.Envs[b.New] = e
	for _, m := range s.Members {
		m.Envs = renameEnvList(m.Envs, b)
	}
	for _, m := range s.Machines {
		m.Envs = renameEnvList(m.Envs, b)
	}
	for _, g := range s.Groups {
		g.Envs = renameEnvList(g.Envs, b)
	}
	for old, current := range s.EnvRenames {
		if current == b.Old {
			s.EnvRenames[old] = b.New
		}
	}
	if s.EnvRenames == nil {
		s.EnvRenames = map[string]string{}
	}
	s.EnvRenames[b.Old] = b.New
	return nil
}

func renameEnvList(names []string, b EnvRenameBody) []string {
	out := append([]string(nil), names...)
	for i, n := range out {
		if n == b.Old {
			out[i] = b.New
		}
	}
	return SortEnvs(out)
}
