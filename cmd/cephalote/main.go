// Command cephalote scans a source tree for weak cryptographic schemes.
package main

import (
	"fmt"
	"os"

	"github.com/Smiduweorc/Cephalote/internal/config"
	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/report"
	"github.com/Smiduweorc/Cephalote/internal/scan"
	"github.com/Smiduweorc/Cephalote/internal/scheme"
	"github.com/spf13/cobra"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		// Cobra already printed usage/errors; exit with the error code.
		os.Exit(2)
	}
}

func rootCmd() *cobra.Command {
	report.Version = version
	root := &cobra.Command{
		Use:           "cephalote",
		Short:         "Scan source code for weak cryptographic schemes",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(scanCmd())
	root.AddCommand(schemesCmd())
	return root
}

func scanCmd() *cobra.Command {
	var (
		format         string
		exitCode       bool
		includeUnknown bool
		minConfidence  string
		configFile     string
		schemeNames    []string
	)

	cmd := &cobra.Command{
		Use:   "scan <dir>",
		Short: "Scan a directory tree for weak crypto",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtSel, err := report.ParseFormat(format)
			if err != nil {
				return err
			}
			minConf, err := parseConfidence(minConfidence)
			if err != nil {
				return err
			}
			// Search mode: resolve the requested schemes (names, aliases, or
			// class selectors like "weak"/"all"). When set, this replaces the
			// default weak-crypto rule set.
			var schemes []scheme.Scheme
			if len(schemeNames) > 0 {
				schemes, err = scheme.Resolve(schemeNames)
				if err != nil {
					return err
				}
			}

			opts := scan.Options{
				IncludeUnknown: includeUnknown,
				MinConfidence:  minConf,
				Schemes:        schemes,
			}

			// A config file supplies excludes, rule overrides, and custom
			// schemes. Explicit flags win over config defaults.
			if configFile != "" {
				cfg, err := config.Load(configFile)
				if err != nil {
					return err
				}
				opts.Exclude = cfg.Exclude
				opts.Disabled = cfg.Disabled
				opts.SeverityOverrides = cfg.Severity
				opts.ExtraSchemes = cfg.CustomSchemes
				if cfg.HasMinConf && !cmd.Flags().Changed("min-confidence") {
					opts.MinConfidence = cfg.MinConfidence
				}
				if cfg.IncludeUnknown && !cmd.Flags().Changed("include-unknown") {
					opts.IncludeUnknown = true
				}
			}

			dir := args[0]
			info, err := os.Stat(dir)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", dir)
			}

			result, err := scan.Run(dir, opts)
			if err != nil {
				return err
			}

			if err := report.Render(cmd.OutOrStdout(), result, fmtSel); err != nil {
				return err
			}

			if exitCode && len(result.Findings) > 0 {
				// Distinct exit code so CI can gate on findings without
				// conflating them with operational errors (exit 2).
				os.Exit(1)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&format, "format", "text", "output format: text|json|sarif")
	f.BoolVar(&exitCode, "exit-code", false, "exit non-zero (1) when findings are present")
	f.BoolVar(&includeUnknown, "include-unknown", false, "run the regex fallback on unrecognized languages")
	f.StringVar(&minConfidence, "min-confidence", "low", "minimum confidence to report: low|high")
	f.StringVar(&configFile, "config", "", "YAML config: excludes, rule overrides, custom schemes")
	f.StringSliceVar(&schemeNames, "scheme", nil,
		"search for specific algorithms instead of the default weak-crypto scan;\n"+
			"accepts names/aliases (e.g. sha256, des3) or class selectors\n"+
			"(all, weak, broken, legacy, strong, contextual). Repeatable/comma-separated")
	return cmd
}

// schemesCmd lists the algorithm catalog so users can discover searchable names.
func schemesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schemes",
		Short: "List the cryptographic algorithms Cephalote can detect or search",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-14s %-8s %s\n", "NAME", "CLASS", "TITLE")
			for _, s := range scheme.All() {
				fmt.Fprintf(w, "%-14s %-8s %s\n", s.Name, s.Class, s.Title)
			}
			fmt.Fprintln(w, "\nSearch with: cephalote scan <dir> --scheme <name|class>")
			return nil
		},
	}
}

func parseConfidence(s string) (finding.Confidence, error) {
	switch finding.Confidence(s) {
	case finding.Low, finding.High:
		return finding.Confidence(s), nil
	default:
		return "", fmt.Errorf("invalid --min-confidence %q (want low or high)", s)
	}
}
