// Command supermcp is the single binary for the supermcp gateway and its
// tooling.
package main

import (
	"fmt"
	"os"
)

const usage = `supermcp — turn REST, GraphQL, SQL, SOAP and MCP systems into MCP tools

Usage:
  supermcp <command> [flags]

Commands:
  serve      run the gateway (API, MCP endpoint, UI)
  migrate    apply database migrations (takes an advisory lock)
  adapter    validate, convert, index and scaffold adapter definitions
  audit      verify the audit trail's hash chain
  keys       rotate the master key, the data keys and the signing key
  compliance access review, cryptography and configuration reports
  dsar       export or erase everything this instance holds about one person
  oauth      list, approve and reject registered OAuth clients
  openapi    print the admin API OpenAPI document
  version    print the build version
`

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serveCmd(os.Args[2:])
	case "migrate":
		err = migrateCmd(os.Args[2:])
	case "adapter":
		err = adapterCmd(os.Args[2:])
	case "audit":
		err = auditCmd(os.Args[2:])
	case "keys":
		err = keysCmd(os.Args[2:])
	case "compliance":
		err = complianceCmd(os.Args[2:])
	case "dsar":
		err = dsarCmd(os.Args[2:])
	case "oauth":
		err = oauthCmd(os.Args[2:])
	case "openapi":
		err = openapiCmd(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
