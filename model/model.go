package model

type AttackTechnique struct {
	AttackTechnique string       `yaml:"attack_technique"`
	DisplayName     string       `yaml:"display_name"`
	AtomicTests     []AtomicTest `yaml:"atomic_tests"`
}

type AtomicTest struct {
	Name               string       `yaml:"name"`
	Description        string       `yaml:"description"`
	SupportedPlatforms []string     `yaml:"supported_platforms"`
	Executor           Executor     `yaml:"executor"`
	Dependencies       []Dependency `yaml:"dependencies"`
}

type Executor struct {
	Command        string `yaml:"command"`
	CleanupCommand string `yaml:"cleanup_command"`
	Name           string `yaml:"name"`
}

type Dependency struct {
	Description      string `yaml:"description"`
	PrereqCommand    string `yaml:"prereq_command"`
	GetPrereqCommand string `yaml:"get_prereq_command"`
}
