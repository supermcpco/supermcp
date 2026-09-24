package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/compliance"
)

const dsarUsage = `Usage: supermcp dsar <subcommand> -user <id|email> [flags]

Subcommands:
  export   write out everything this instance holds about one person, as a
           directory of JSON files or a zip
  erase    pseudonymise that person's name and email address wherever they
           appear, including the audit stream, and report what was left and why

Both act on one account. Neither revokes anything: a session or an API key
that worked before still works afterwards, because ending somebody's access
is a separate decision from erasing their name.
`

func dsarCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, dsarUsage)
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "export":
		return dsarExport(args[1:])
	case "erase":
		return dsarErase(args[1:])
	default:
		fmt.Fprint(os.Stderr, dsarUsage)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func dsarExport(args []string) error {
	fs := flag.NewFlagSet("dsar export", flag.ContinueOnError)
	user := fs.String("user", "", "the account, by id or email address")
	out := fs.String("out", "", "where to write it: a directory, or a path ending in .zip (default: ./dsar-<account id>)")
	format := fs.String("format", "text", "the manifest printed to standard output: text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		fmt.Fprint(os.Stderr, dsarUsage)
		return fmt.Errorf("-user is required")
	}
	if err := checkFormat(*format, "text", "json"); err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()
	d, err := complianceSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	subject, err := compliance.FindSubject(ctx, d.Deps, *user)
	if err != nil {
		return err
	}
	// The read is recorded before anything is handed over, and blocking is
	// deliberate: an export whose record of itself was dropped is an
	// export nobody can account for.
	writer := audit.NewWriter(d.Deps.DB, d.Log, //nolint:contextcheck // the writer owns its lifetime
		audit.Options{OnUnavailable: audit.UnavailableBlock})
	defer writer.Close()

	ex, err := compliance.BuildExport(ctx, d.Deps, subject, compliance.ExportOptions{Audit: writer})
	if err != nil {
		return err
	}
	dest := *out
	if dest == "" {
		dest = "dsar-" + subject.UserID
	}
	path, err := ex.WriteTo(dest)
	if err != nil {
		return err
	}

	if *format == "json" {
		if err := ex.WriteJSON(os.Stdout); err != nil {
			return err
		}
	} else if err := ex.WriteText(os.Stdout); err != nil {
		return err
	}
	fmt.Printf("\nwritten to %s\n", path)
	return nil
}

// dsarErase asks before it acts. The change is not reversible: the
// address it replaces is not stored anywhere afterwards, which is the
// point of it.
func dsarErase(args []string) error {
	fs := flag.NewFlagSet("dsar erase", flag.ContinueOnError)
	user := fs.String("user", "", "the account, by id or email address")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	format := fs.String("format", "text", "text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		fmt.Fprint(os.Stderr, dsarUsage)
		return fmt.Errorf("-user is required")
	}
	if err := checkFormat(*format, "text", "json"); err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()
	d, err := complianceSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	subject, err := compliance.FindSubject(ctx, d.Deps, *user)
	if err != nil {
		return err
	}
	if !*yes {
		ok, err := confirmErase(subject)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("nothing was changed")
		}
	}

	writer := audit.NewWriter(d.Deps.DB, d.Log, //nolint:contextcheck // the writer owns its lifetime
		audit.Options{OnUnavailable: audit.UnavailableBlock})
	defer writer.Close()

	res, err := compliance.Erase(ctx, d.Deps, subject, compliance.EraseOptions{Audit: writer})
	// A failure after the rows were rewritten still has a report worth
	// printing, so the result is rendered whenever there is one.
	if res != nil {
		if *format == "json" {
			if werr := res.WriteJSON(os.Stdout); werr != nil {
				return werr
			}
		} else if werr := res.WriteText(os.Stdout); werr != nil {
			return werr
		}
	}
	if err != nil {
		return err
	}
	fmt.Print("\nRun `supermcp audit verify` to prove the chain is still intact.\n")
	return nil
}

// confirmErase makes the operator type the address. A yes/no prompt is
// answered by reflex; typing the address that is about to disappear is
// not, and this is the one command here that cannot be undone.
func confirmErase(s *compliance.Subject) (bool, error) {
	fmt.Printf("This will pseudonymise %s\n", s.Summary())
	fmt.Printf("everywhere it appears, including the audit stream. It cannot be undone.\n")
	fmt.Printf("Type the email address to confirm: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("could not read the confirmation: %w", err)
	}
	return strings.EqualFold(strings.TrimSpace(line), s.Email), nil
}
