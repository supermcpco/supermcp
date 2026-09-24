package parser

// FromCurl turns one cURL command into a connector with one tool.
//
// The command is a shell command, and that is the whole difficulty. It is
// read the way a shell reads a word — quotes, escapes, backslash
// continuations — but it is never run, and anything that would need a
// shell to produce a value is refused rather than quietly dropped:
//
//   - $(command) and `command` are refused. Dropping them would build a
//     request that is missing a value someone believed they had supplied.
//   - -d @file, -F name=@file and --upload-file read from a filesystem
//     this does not have, so they are refused too.
//   - $NAME and ${NAME}, on the other hand, are not execution. They name
//     a value the person keeps in their environment, which is exactly
//     what a credential is, so each becomes one.
//
// What the command carried inline is treated the same way. A token in an
// Authorization header, a password in -u, an API key in a query
// parameter: each becomes a declared credential and a {{env.NAME}}
// placeholder, and a finding says where it went, because a working
// command that someone pastes contains a working key.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// FromCurl converts a cURL command into an adapter.
func FromCurl(command []byte, opts Options) (*adapter.Adapter, []ImportFinding, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if len(command) > maxBytes {
		return nil, nil, fmt.Errorf("command is %d bytes, over the %d byte limit", len(command), maxBytes)
	}
	if opts.Region != "" && !adapter.Regions[opts.Region] {
		return nil, nil, fmt.Errorf("region %q is not a known region", opts.Region)
	}
	if opts.Category != "" && !adapter.Categories[opts.Category] {
		return nil, nil, fmt.Errorf("category %q is not a known category", opts.Category)
	}

	text := string(command)
	first, rest := curlSplitCommands(text)
	if strings.TrimSpace(first) == "" {
		return nil, nil, errors.New("there is no curl command here")
	}

	c := &curlImporter{builder: newBuilder(opts)}
	tokens, tail, err := curlTokenize(first)
	if err != nil {
		return nil, c.refuse(err), err
	}
	if strings.TrimSpace(tail) != "" {
		c.add(Info, "command", "the command continues with %q after the request; a connector makes the request and nothing else, so the rest is ignored", truncateTo(strings.TrimSpace(tail), 60))
	}
	if len(tokens) == 0 || !strings.EqualFold(tokens[0], "curl") {
		return nil, nil, errors.New("the command does not start with curl")
	}
	c.read(tokens[1:])
	if c.refused != "" {
		err := errors.New(c.refused)
		return nil, c.refuse(err), err
	}
	if strings.TrimSpace(c.url) == "" {
		err := errors.New("the command names no URL to call; a connector has to know what to request")
		return nil, c.refuse(err), err
	}

	origin, path, rawQuery := splitRequestURL(c.url)
	if origin == "" {
		err := fmt.Errorf("the URL %q has no host, so there is nothing to call", truncateTo(c.url, 80))
		return nil, c.refuse(err), err
	}
	host := ""
	if u, err := url.Parse(origin); err == nil {
		host = u.Host
	}
	c.identify(hostName(host), "Imported from a curl command against "+host+".")
	if c.opts.Name == "" {
		// The slug wants the organisation's name; what a person reads wants
		// the host they recognise.
		c.out.Metadata.Name = host
	}
	c.out.Transport.Type = adapter.TransportHTTP
	c.out.Transport.BaseURL = origin
	c.locate(origin)
	c.build(path, rawQuery, host)

	if strings.TrimSpace(rest) != "" {
		c.op = ""
		c.add(Blocker, "command", "there is more than one curl command here; only the first was read — import the others separately, or delete them and preview again")
	}
	return c.finish()
}

// curlImporter carries the state of one command conversion.
type curlImporter struct {
	*builder

	method      string
	url         string
	headers     []curlHeader
	data        []curlData
	form        []curlField
	user        string
	bearer      string
	cookies     []string
	getWithData bool
	headOnly    bool
	jsonFlag    bool
	refused     string
}

// refuse records why the command could not be imported as a blocker, so
// the reason reaches the preview as a finding and not only as the text of
// an error.
func (c *curlImporter) refuse(err error) []ImportFinding {
	c.op = ""
	c.add(Blocker, "command", "%s", err.Error())
	return c.findings
}

type curlHeader struct{ name, value string }

// curlData is one -d/--data/--data-urlencode argument.
type curlData struct {
	text      string
	urlencode bool
}

type curlField struct{ name, value string }

// --- reading the command ---------------------------------------------------

var reCurlStart = regexp.MustCompile(`(?m)^\s*(?:[$#>]\s+)?curl\b`)

// curlSplitCommands returns the first command and whatever commands
// follow it, so the importer can say that it read one of several rather
// than silently importing a third of what was pasted.
func curlSplitCommands(text string) (first, rest string) {
	// A continued line is part of the command above it, not a new one.
	joined := regexp.MustCompile(`\\[ \t]*\r?\n`).ReplaceAllString(text, " ")
	locs := reCurlStart.FindAllStringIndex(joined, -1)
	if len(locs) == 0 {
		return joined, ""
	}
	start := locs[0][0]
	if len(locs) == 1 {
		return joined[start:], ""
	}
	return joined[start:locs[1][0]], joined[locs[1][0]:]
}

// curlTokenize splits a command into shell words. It returns the words,
// whatever followed a pipeline or redirection operator, and an error for
// anything that would need a shell to run.
func curlTokenize(cmd string) (tokens []string, tail string, err error) {
	var (
		word    strings.Builder
		started bool
		single  bool
		double  bool
	)
	flush := func() {
		if started {
			tokens = append(tokens, word.String())
			word.Reset()
			started = false
		}
	}
	runes := []rune(cmd)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case single:
			if r == '\'' {
				single = false
				continue
			}
			word.WriteRune(r)
			started = true
		case double:
			switch r {
			case '"':
				double = false
			case '\\':
				if i+1 < len(runes) {
					next := runes[i+1]
					switch next {
					case '"', '\\', '$', '`', '\n':
						if next != '\n' {
							word.WriteRune(next)
							started = true
						}
						i++
						continue
					}
				}
				word.WriteRune(r)
				started = true
			case '`':
				return nil, "", errCurlShell("a backquoted command")
			case '$':
				if i+1 < len(runes) && runes[i+1] == '(' {
					return nil, "", errCurlShell("a $(...) command substitution")
				}
				name, width := curlShellVar(runes[i:])
				if name == "" {
					word.WriteRune(r)
					started = true
					continue
				}
				word.WriteString("{{env." + envName(name) + "}}")
				started = true
				i += width - 1
			default:
				word.WriteRune(r)
				started = true
			}
		default:
			switch r {
			case '\'':
				single = true
				started = true
			case '"':
				double = true
				started = true
			case '`':
				return nil, "", errCurlShell("a backquoted command")
			case '\\':
				if i+1 < len(runes) {
					if runes[i+1] == '\n' || (runes[i+1] == '\r' && i+2 < len(runes) && runes[i+2] == '\n') {
						// A line continuation joins two lines into one word
						// boundary, not into one word.
						for i+1 < len(runes) && (runes[i+1] == '\r' || runes[i+1] == '\n') {
							i++
						}
						flush()
						continue
					}
					word.WriteRune(runes[i+1])
					started = true
					i++
					continue
				}
			case '$':
				if i+1 < len(runes) && runes[i+1] == '(' {
					return nil, "", errCurlShell("a $(...) command substitution")
				}
				name, width := curlShellVar(runes[i:])
				if name == "" {
					word.WriteRune(r)
					started = true
					continue
				}
				word.WriteString("{{env." + envName(name) + "}}")
				started = true
				i += width - 1
			case '|', ';', '&', '>':
				flush()
				return tokens, string(runes[i:]), nil
			case '<':
				return nil, "", errors.New("the command reads its body from the shell with <, which a connector cannot do; paste the body into the command with -d instead")
			case ' ', '\t', '\n', '\r':
				flush()
			default:
				word.WriteRune(r)
				started = true
			}
		}
	}
	if single || double {
		return nil, "", errors.New("the command has a quote that is never closed")
	}
	flush()
	return tokens, "", nil
}

func errCurlShell(what string) error {
	return errors.New("the command contains " + what + "; running a shell is not something a connector does, so work out the value yourself and paste it, or leave it as $NAME and it becomes a credential")
}

var reShellVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// curlShellVar reads $NAME or ${NAME} at the start of runes, returning the
// name and how many runes it spans.
func curlShellVar(runes []rune) (string, int) {
	if len(runes) < 2 || runes[0] != '$' {
		return "", 0
	}
	if runes[1] == '{' {
		for i := 2; i < len(runes); i++ {
			if runes[i] == '}' {
				name := string(runes[2:i])
				if reShellVarName.FindString(name) != name {
					return "", 0
				}
				return name, i + 1
			}
		}
		return "", 0
	}
	name := reShellVarName.FindString(string(runes[1:]))
	if name == "" {
		return "", 0
	}
	return name, 1 + len([]rune(name))
}

// --- flags -----------------------------------------------------------------

// curlValueFlags are the long options that take a value. Knowing which
// they are is not pedantry: an unrecognised one leaves its value loose,
// and a loose value is mistaken for the URL.
var curlValueFlags = map[string]bool{
	"request": true, "header": true, "data": true, "data-raw": true, "data-ascii": true,
	"data-binary": true, "data-urlencode": true, "json": true, "form": true, "form-string": true,
	"user": true, "cookie": true, "cookie-jar": true, "user-agent": true, "referer": true,
	"output": true, "upload-file": true, "url": true, "write-out": true, "max-time": true,
	"connect-timeout": true, "retry": true, "retry-delay": true, "retry-max-time": true,
	"cert": true, "key": true, "cacert": true, "capath": true, "cert-type": true, "key-type": true,
	"pass": true, "proxy": true, "proxy-user": true, "noproxy": true, "resolve": true,
	"connect-to": true, "limit-rate": true, "speed-limit": true, "speed-time": true,
	"oauth2-bearer": true, "aws-sigv4": true, "config": true, "dump-header": true,
	"interface": true, "local-port": true, "trace": true, "trace-ascii": true, "stderr": true,
	"range": true, "continue-at": true, "max-filesize": true, "max-redirs": true,
	"proto": true, "expect100-timeout": true, "happy-eyeballs-timeout-ms": true,
	"unix-socket": true, "hostpubmd5": true, "engine": true, "krb": true, "delegation": true,
	"tlsuser": true, "tlspassword": true, "ciphers": true, "tls13-ciphers": true, "pinnedpubkey": true,
}

// curlShortValueFlags are the short options that take a value.
var curlShortValueFlags = map[rune]bool{
	'X': true, 'H': true, 'd': true, 'F': true, 'u': true, 'b': true, 'c': true, 'A': true,
	'e': true, 'o': true, 'T': true, 'w': true, 'm': true, 'x': true, 'U': true, 'E': true,
	'y': true, 'Y': true, 'z': true, 'r': true, 'C': true, 'K': true, 'D': true,
}

// read walks the arguments after `curl`.
func (c *curlImporter) read(args []string) {
	next := func(i *int) string {
		if *i+1 < len(args) {
			*i++
			return args[*i]
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--"):
			name, value, hasValue := strings.Cut(arg[2:], "=")
			if curlValueFlags[name] && !hasValue {
				value = next(&i)
			}
			c.flag(name, value, curlValueFlags[name])
		case len(arg) > 1 && strings.HasPrefix(arg, "-"):
			cluster := []rune(arg[1:])
			for j := 0; j < len(cluster); j++ {
				ch := cluster[j]
				if !curlShortValueFlags[ch] {
					c.shortFlag(ch)
					continue
				}
				value := string(cluster[j+1:])
				if value == "" {
					value = next(&i)
				}
				c.flag(curlShortName(ch), value, true)
				j = len(cluster)
			}
		default:
			if c.url == "" {
				c.url = arg
				continue
			}
			c.add(Review, "command", "the command names more than one URL; only %q is imported", truncateTo(c.url, 60))
		}
	}
}

// curlShortName maps a short option onto the long one it is an alias for,
// so there is one place that decides what each does.
func curlShortName(ch rune) string {
	switch ch {
	case 'X':
		return "request"
	case 'H':
		return "header"
	case 'd':
		return "data"
	case 'F':
		return "form"
	case 'u':
		return "user"
	case 'b':
		return "cookie"
	case 'c':
		return "cookie-jar"
	case 'A':
		return "user-agent"
	case 'e':
		return "referer"
	case 'o':
		return "output"
	case 'T':
		return "upload-file"
	case 'w':
		return "write-out"
	case 'm':
		return "max-time"
	case 'x':
		return "proxy"
	case 'U':
		return "proxy-user"
	case 'E':
		return "cert"
	default:
		return string(ch)
	}
}

func (c *curlImporter) shortFlag(ch rune) {
	switch ch {
	case 'G':
		c.getWithData = true
	case 'I':
		c.headOnly = true
	case 'k':
		c.add(Review, "command", "the command turns off certificate checks with -k; the connector always checks them, so a host with a bad certificate will fail where the command worked")
	case 'n':
		c.add(Review, "command", "the command reads credentials from a .netrc file; there is none here, so set the connector's credentials instead")
	case 's', 'S', 'v', 'L', 'i', 'f', 'g', 'j', 'N', 'O', 'R', '#', '4', '6', '0', '1', '2', '3', 'a', 'p', 'q', 'Z', 'V', 'h', 'M':
		// Output, progress and connection options: they say nothing about
		// the request a connector would make.
	default:
		c.add(Info, "command", "the option -%c says nothing a connector can act on; it is ignored", ch)
	}
}

func (c *curlImporter) flag(name, value string, takesValue bool) {
	switch name {
	case "request":
		c.method = strings.ToUpper(strings.TrimSpace(value))
	case "url":
		if c.url == "" {
			c.url = value
		}
	case "header":
		key, v, found := strings.Cut(value, ":")
		if !found {
			c.add(Info, "command", "the header %q has no colon in it; it is ignored", truncateTo(value, 40))
			return
		}
		c.headers = append(c.headers, curlHeader{name: strings.TrimSpace(key), value: strings.TrimSpace(v)})
	case "data", "data-raw", "data-ascii", "data-binary":
		if strings.HasPrefix(value, "@") && name != "data-raw" {
			c.refuseFile(value, "--"+name)
			return
		}
		c.data = append(c.data, curlData{text: value})
	case "data-urlencode":
		if strings.Contains(value, "@") && curlURLEncodeReadsFile(value) {
			c.refuseFile(value, "--data-urlencode")
			return
		}
		c.data = append(c.data, curlData{text: value, urlencode: true})
	case "json":
		c.jsonFlag = true
		if strings.HasPrefix(value, "@") {
			c.refuseFile(value, "--json")
			return
		}
		c.data = append(c.data, curlData{text: value})
	case "form", "form-string":
		c.formField(value, name)
	case "user":
		c.user = value
	case "oauth2-bearer":
		c.bearer = value
	case "cookie":
		if strings.HasPrefix(value, "@") || !strings.Contains(value, "=") {
			c.add(Review, "command", "the command reads its cookies from the file %q; the connector has no such file, so set any cookie it needs as a header", truncateTo(strings.TrimPrefix(value, "@"), 40))
			return
		}
		c.cookies = append(c.cookies, value)
	case "user-agent", "referer":
		// A connector identifies itself; copying the command's identity
		// across would be a small lie told on every call.
	case "upload-file":
		c.refuseFile(value, "--upload-file")
	case "config":
		c.refused = "the command reads more options from a file with --config, which is not here; paste the whole command instead"
	case "aws-sigv4":
		c.add(Review, "command", "the command signs with AWS SigV4; an adapter signs differently, so the connector is created unauthenticated and needs its auth filled in")
	case "cert", "key", "cacert", "capath":
		c.add(Review, "command", "the command presents a client certificate; the certificate and key are files this import cannot read, so set the connector's auth by hand")
	case "proxy", "proxy-user":
		c.add(Info, "command", "the command goes through a proxy; the connector's own egress settings decide that instead")
	case "output", "write-out", "dump-header", "trace", "trace-ascii", "stderr", "cookie-jar":
		// Where curl puts what it received. A connector answers the model.
	default:
		if takesValue {
			c.add(Info, "command", "the option --%s says nothing a connector can act on; it is ignored", name)
		}
	}
}

// curlURLEncodeReadsFile reports whether a --data-urlencode argument
// takes its content from a file: name@file and @file do, name=value and
// =value do not.
func curlURLEncodeReadsFile(value string) bool {
	at := strings.IndexByte(value, '@')
	eq := strings.IndexByte(value, '=')
	if at < 0 {
		return false
	}
	return eq < 0 || at < eq
}

func (c *curlImporter) refuseFile(value, flag string) {
	c.refused = fmt.Sprintf("%s reads from %q, and there is no filesystem behind a connector; paste the content into the command instead", flag, truncateTo(strings.TrimPrefix(value, "@"), 40))
}

func (c *curlImporter) formField(value, flag string) {
	name, content, found := strings.Cut(value, "=")
	if !found {
		c.add(Info, "command", "the form part %q has no name; it is ignored", truncateTo(value, 40))
		return
	}
	if flag == "form" && (strings.HasPrefix(content, "@") || strings.HasPrefix(content, "<")) {
		c.refuseFile(content, "-F "+name)
		return
	}
	// A part may carry ;type=... and ;filename=... after its value.
	if i := strings.IndexByte(content, ';'); i >= 0 && flag == "form" {
		content = content[:i]
	}
	c.form = append(c.form, curlField{name: name, value: content})
}

// --- building the tool -----------------------------------------------------

func (c *curlImporter) build(path, rawQuery, host string) {
	method := c.chooseMethod()
	loc := "command"
	c.op = method + " " + path

	t := adapter.Tool{}
	switch method {
	case "GET", "HEAD":
		t.Annotations = &adapter.Annotations{ReadOnlyHint: ptr(true)}
	case "DELETE":
		t.Annotations = &adapter.Annotations{DestructiveHint: ptr(true)}
	case "POST", "PUT", "PATCH", "OPTIONS":
	default:
		c.add(Review, loc, "the command sends %q, which is not a method an adapter can use; the tool sends POST instead", method)
		method = "POST"
	}

	in := newParams(c.builder, loc)
	t.Name = c.toolName(method+"_"+pathWords(path), loc)
	t.Operation.Method = method
	t.Operation.Path = c.templatePath(path, in, loc)

	c.applyAuth(loc)
	c.applyHeaders(&t, in, loc)
	c.applyQuery(&t, rawQuery, in, loc)
	if method != "GET" && method != "HEAD" {
		c.applyBody(&t, in, loc)
	} else if len(c.data) > 0 && !c.getWithData {
		c.add(Info, loc, "the command's data is not sent on a %s request; it is dropped", method)
	}
	t.Input = in.schema()
	t.Description = fmt.Sprintf("Sends %s %s to %s, as the curl command this connector was imported from did.",
		method, readableTemplate(or(t.Operation.Path, "/")), host)
	c.out.Tools = append(c.out.Tools, t)
}

func (c *curlImporter) chooseMethod() string {
	switch {
	case c.method != "":
		return c.method
	case c.headOnly:
		return "HEAD"
	case c.getWithData:
		return "GET"
	case len(c.data) > 0 || len(c.form) > 0:
		return "POST"
	default:
		return "GET"
	}
}

// Documentation writes the part of a URL a caller fills in as {id} or
// {{id}}; neither is something curl would send, so both become
// parameters.
var reCurlPathVar = regexp.MustCompile(`\{\{?([A-Za-z_][A-Za-z0-9_.\-]*)\}?\}`)

func (c *curlImporter) templatePath(path string, in *params, loc string) string {
	if path == "" {
		return ""
	}
	path = c.adopt(path)
	return reCurlPathVar.ReplaceAllStringFunc(path, func(m string) string {
		inner := strings.Trim(m, "{}")
		if strings.HasPrefix(inner, "env.") || strings.HasPrefix(inner, "params.") {
			return m // already a placeholder this importer wrote
		}
		c.add(Info, loc, "the URL has %s where a value goes; the tool asks for it as a parameter", m)
		schema := mapping()
		mapSet(schema, "type", str("string"))
		return in.declare(inner, "path segment", "The "+inner+" to call", schema, true)
	})
}

// adopt declares a credential for every {{env.NAME}} the tokenizer wrote
// when it read a $NAME out of the command, at the moment the string that
// holds it reaches the adapter. Declaring them any earlier would leave a
// credential behind for a $NAME in a part of the command that was
// dropped, and the validator rightly complains about one nothing reads.
func (c *curlImporter) adopt(s string) string {
	for _, m := range reAdoptEnv.FindAllStringSubmatch(s, -1) {
		if !c.hasCredential(m[1]) {
			c.credential(m[1], "Read from $"+m[1]+" in the command this connector was imported from", true)
		}
	}
	return s
}

var reAdoptEnv = regexp.MustCompile(`\{\{env\.([A-Z][A-Z0-9_]*)\}\}`)

// Headers curl or the transport sets for itself.
var curlSkippedHeaders = map[string]bool{
	"accept-encoding": true, "content-length": true, "host": true, "connection": true,
	"user-agent": true, "expect": true,
}

func (c *curlImporter) applyHeaders(t *adapter.Tool, in *params, loc string) {
	for _, h := range c.headers {
		lower := strings.ToLower(h.name)
		if curlSkippedHeaders[lower] || h.name == "" {
			continue
		}
		if lower == "authorization" {
			continue // taken as auth
		}
		if h.value == "" {
			continue
		}
		value := c.adopt(h.value)
		switch {
		case strings.Contains(value, "{{env."):
			t.Operation.Headers.Set(h.name, value)
		case (looksSecretName(h.name) || looksSecretValue(value)) && c.out.Auth.Type == adapter.AuthNone:
			// The one header carrying a key is how this API signs in.
			name := envName(h.name)
			c.out.Auth = adapter.Auth{Type: adapter.AuthAPIKey, In: "header", Name: h.name, Value: c.credential(name, "Sent as the "+h.name+" header", true)}
			c.add(Review, loc, "the %s header carries what looks like a key; it is not stored in the connector — set the credential %s and the connector will send it on every call", h.name, name)
		case looksSecretName(h.name) || looksSecretValue(value):
			name := envName(h.name)
			t.Operation.Headers.Set(h.name, c.credential(name, "Sent as the "+h.name+" header", true))
			c.add(Review, loc, "the %s header carries what looks like a key; it is not stored in the connector — set the credential %s instead", h.name, name)
		default:
			// A header a command carries is nearly always something the API
			// requires rather than something a caller varies — an API
			// version, a content type, an accept. It stays as written; a
			// model has no business changing it.
			t.Operation.Headers.Set(h.name, value)
		}
	}
	if len(c.cookies) > 0 {
		value := c.adopt(strings.Join(c.cookies, "; "))
		if looksSecretValue(value) {
			name := envName("cookie")
			t.Operation.Headers.Set("Cookie", c.credential(name, "The Cookie header the command sent", true))
			c.add(Review, loc, "the command's cookie looks like a session; it is not stored in the connector — set the credential %s instead", name)
		} else {
			t.Operation.Headers.Set("Cookie", value)
		}
	}
}

func (c *curlImporter) applyQuery(t *adapter.Tool, rawQuery string, in *params, loc string) {
	pairs := curlQueryPairs(rawQuery)
	if c.getWithData {
		for _, d := range c.data {
			pairs = append(pairs, curlQueryPairs(d.text)...)
		}
	}
	if len(pairs) == 0 {
		return
	}
	q := mapping()
	for _, p := range pairs {
		value := c.adopt(p.value)
		switch {
		case strings.Contains(value, "{{env."):
			mapSet(q, p.key, str(value))
		case (looksSecretName(p.key) || looksSecretValue(value)) && value != "":
			name := envName(p.key)
			mapSet(q, p.key, str(c.credential(name, "Sent as the "+p.key+" query parameter", true)))
			c.add(Review, loc, "the %s query parameter carries what looks like a key; it is not stored in the connector — set the credential %s instead", p.key, name)
		default:
			schema := mapping()
			mapSet(schema, "type", str("string"))
			if value != "" {
				mapSet(schema, "default", str(value))
			}
			mapSet(q, p.key, str(in.declare(p.key, "query parameter", "", schema, false)))
		}
	}
	t.Operation.Query = &adapter.Node{N: q}
}

type curlPair struct{ key, value string }

func curlQueryPairs(raw string) []curlPair {
	var out []curlPair
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		if k, err := url.QueryUnescape(key); err == nil {
			key = k
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		if strings.TrimSpace(key) == "" {
			continue
		}
		out = append(out, curlPair{key: key, value: value})
	}
	return out
}

// --- auth ------------------------------------------------------------------

func (c *curlImporter) applyAuth(loc string) {
	if c.user != "" {
		user, pass, found := strings.Cut(c.adopt(c.user), ":")
		c.out.Auth = adapter.Auth{Type: adapter.AuthBasic, Username: c.curlSecret(user, credUsername, "HTTP basic username", false, loc)}
		if found {
			c.out.Auth.Password = c.curlSecret(pass, credPassword, "HTTP basic password", true, loc)
		}
		c.add(Review, loc, "the command signs in with -u; the username and password are not stored in the connector — set the credentials it now declares")
		return
	}
	if c.bearer != "" {
		c.out.Auth = adapter.Auth{Type: adapter.AuthBearer, Token: c.curlSecret(c.adopt(c.bearer), credToken, "Bearer token", true, loc)}
		return
	}
	for _, h := range c.headers {
		if !strings.EqualFold(h.name, "authorization") || h.value == "" {
			continue
		}
		c.authorizationHeader(c.adopt(h.value), loc)
		return
	}
}

func (c *curlImporter) authorizationHeader(value, loc string) {
	scheme, rest, found := strings.Cut(value, " ")
	if !found {
		scheme, rest = "Bearer", value
	}
	rest = strings.TrimSpace(rest)
	if strings.EqualFold(scheme, "Basic") && !strings.Contains(rest, "{{env.") {
		if decoded, err := base64.StdEncoding.DecodeString(rest); err == nil {
			user, pass, ok := strings.Cut(string(decoded), ":")
			if ok {
				c.out.Auth = adapter.Auth{
					Type:     adapter.AuthBasic,
					Username: c.curlSecret(user, credUsername, "HTTP basic username", false, loc),
					Password: c.curlSecret(pass, credPassword, "HTTP basic password", true, loc),
				}
				c.add(Review, loc, "the Authorization header carried a username and password; neither is stored in the connector — set the credentials it now declares")
				return
			}
		}
	}
	auth := adapter.Auth{Type: adapter.AuthBearer, Token: c.curlSecret(rest, credToken, "Sent in the Authorization header", true, loc)}
	if !strings.EqualFold(scheme, "Bearer") {
		auth.Prefix = scheme
	}
	c.out.Auth = auth
}

// curlSecret keeps a value that already reads a credential and moves a
// literal one into a credential of its own.
func (c *curlImporter) curlSecret(value, credName, description string, secret bool, loc string) string {
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return ""
	case strings.Contains(value, "{{env."):
		return value
	case !secret && !looksSecretValue(value):
		// A username is not a secret, but it is still someone's account,
		// and a connector that other people use should not carry it.
		return c.credential(credName, description, false)
	default:
		c.add(Review, loc, "the command carried a credential in plain text; it is not stored in the connector — set %s to the value you want used", envName(credName))
		return c.credential(credName, description, true)
	}
}

// --- body ------------------------------------------------------------------

func (c *curlImporter) applyBody(t *adapter.Tool, in *params, loc string) {
	switch {
	case len(c.form) > 0:
		c.formBody(t, in, loc)
	case c.getWithData || len(c.data) == 0:
		return
	default:
		c.dataBody(t, in, loc)
	}
}

func (c *curlImporter) formBody(t *adapter.Tool, in *params, loc string) {
	value := mapping()
	for _, f := range c.form {
		content := c.adopt(f.value)
		if strings.Contains(content, "{{env.") {
			mapSet(value, f.name, str(content))
			continue
		}
		schema := mapping()
		mapSet(schema, "type", str("string"))
		if content != "" {
			mapSet(schema, "default", str(content))
		}
		mapSet(value, f.name, str(in.declare(f.name, "form part", "", schema, false)))
	}
	t.Operation.Body = &adapter.Body{Encoding: "multipart", Value: &adapter.Node{N: value}}
	if len(c.data) > 0 {
		c.add(Review, loc, "the command sends both form parts and data; only the form parts are sent, because one request has one body")
	}
}

func (c *curlImporter) dataBody(t *adapter.Tool, in *params, loc string) {
	// --data-urlencode says the body is a form, whatever else is alongside.
	urlencoded := false
	for _, d := range c.data {
		if d.urlencode {
			urlencoded = true
		}
	}
	joined := make([]string, 0, len(c.data))
	for _, d := range c.data {
		joined = append(joined, d.text)
	}
	raw := c.adopt(strings.Join(joined, "&"))

	if !urlencoded {
		if node, err := adapter.NodeFromJSON([]byte(raw)); err == nil && node != nil && node.N != nil && node.N.Kind == yaml.MappingNode {
			t.Operation.Body = &adapter.Body{Encoding: "json", Value: &adapter.Node{N: c.jsonBody(node.N, in, loc)}}
			return
		}
	}
	if urlencoded || curlLooksFormEncoded(raw) {
		value := mapping()
		for _, p := range curlQueryPairs(raw) {
			if strings.Contains(p.value, "{{env.") {
				mapSet(value, p.key, str(p.value))
				continue
			}
			schema := mapping()
			mapSet(schema, "type", str("string"))
			if p.value != "" {
				mapSet(schema, "default", str(p.value))
			}
			mapSet(value, p.key, str(in.declare(p.key, "form field", "", schema, false)))
		}
		if len(value.Content) > 0 {
			t.Operation.Body = &adapter.Body{Encoding: "form", Value: &adapter.Node{N: value}}
			return
		}
	}
	// Anything else goes as it stands, with the command's text as the
	// default so the tool can be called with something else.
	schema := mapping()
	mapSet(schema, "type", str("string"))
	if !strings.Contains(raw, "{{env.") {
		mapSet(schema, "default", str(raw))
	}
	contentType := "text/plain"
	if c.jsonFlag {
		contentType = "application/json"
	}
	for _, h := range c.headers {
		if strings.EqualFold(h.name, "content-type") {
			contentType = h.value
		}
	}
	t.Operation.Headers.Set("Content-Type", contentType)
	t.Operation.Body = &adapter.Body{Encoding: "raw", Value: &adapter.Node{N: str(in.declare("body", "body", "The request body, sent as "+contentType, schema, true))}}
	c.add(Info, loc, "the command's body is neither JSON nor a form, so it is one parameter with the command's text as its default")
}

// jsonBody turns each top-level field of a JSON body into a parameter,
// keeping what the command sent as the default. A model fills in named
// fields far more reliably than it writes a document.
func (c *curlImporter) jsonBody(n *yaml.Node, in *params, loc string) *yaml.Node {
	out := mapping()
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		if val.Kind == yaml.ScalarNode && val.Tag == "!!str" && strings.Contains(val.Value, "{{env.") {
			mapSet(out, key, typedScalar(val))
			continue
		}
		schema := inferSchema(val, 0)
		required := false
		if def := typedScalar(val); def != nil && val.Tag != "!!null" {
			mapSet(schema, "default", def)
		} else if val.Kind != yaml.ScalarNode {
			required = true
		}
		mapSet(out, key, str(in.declare(key, "body field", "", schema, required)))
	}
	if len(out.Content) == 0 {
		c.add(Info, loc, "the command's JSON body is empty; the tool sends an empty object")
	}
	return out
}

var reFormEncoded = regexp.MustCompile(`\A[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*\z`)

func curlLooksFormEncoded(raw string) bool {
	return reFormEncoded.MatchString(strings.TrimSpace(raw))
}

// truncateTo shortens a string for a message, cutting on a rune boundary
// so a message never ends in half a character.
func truncateTo(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
