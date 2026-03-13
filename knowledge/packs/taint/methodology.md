# Taint Analysis Methodology — Rails Injection Vulnerabilities

## Overview

This methodology traces user-controlled data (tainted input) from entry points (sources) through the application to dangerous operations (sinks). A vulnerability exists when tainted data reaches a sink without adequate sanitization.

## Hunting Process

### Step 1: Identify the Entry Point

Start from either a scanner detection or an attack surface map target.

- **From detection:** Read the flagged code and its surrounding context (±30 lines). Identify which controller action or API endpoint contains or invokes the flagged code.
- **From attack surface:** Start at the controller action. Identify the HTTP route and method.

### Step 2: Map User-Controlled Inputs

Identify all sources of user input in the action:

- `params[:key]` — URL/form/JSON body parameters
- `params.require(:model).permit(:fields)` — Strong Parameters (note which fields are permitted)
- `request.headers["X-Custom"]` — HTTP headers
- `cookies[:key]` — Cookie values
- `request.body` — Raw request body
- `request.url`, `request.path` — URL components

**Critical check:** If Strong Parameters are used (`require/permit`), note exactly which fields are permitted. Unpermitted fields cannot reach the sink through the standard Rails param flow.

### Step 3: Follow the Data Flow

Trace tainted data through the call chain:

1. **Controller** → typically calls a Service or Finder
2. **Service/Finder** → constructs queries or performs operations
3. **Model** → interacts with database or system

At each hop:
- Note the method being called and the file:line
- Check if the data is transformed, cast, or sanitized
- Check if the data is passed directly or wrapped

### Step 4: Check for Sanitizers

At each step in the data flow, look for:

- **Type casting:** `.to_i`, `.to_f` — eliminates string injection
- **Allowlist validation:** checking value against a set of known-safe values
- **Parameterized queries:** `where(column: value)` vs `where("column = '#{value}'")`
- **Framework sanitizers:** `sanitize()`, `strip_tags()`, `ERB::Util.html_escape()`
- **Strong Parameters:** `params.require(:x).permit(:y)` — prevents mass assignment and limits input
- **Encoding:** `URI.encode_www_form_component()`, `CGI.escape()`

If any sanitizer fully breaks the taint path, the code is not vulnerable through this path. Log as dead end.

### Step 5: Identify the Sink

Confirm the tainted data reaches a dangerous operation:

- **SQL:** `where("...")`, `find_by_sql()`, `connection.execute()`, `order()`, `group()`, `having()`, `pluck()`, `select()` with string interpolation
- **XSS:** `html_safe`, `raw()`, `content_tag` with unsanitized attributes, `render inline:`
- **Command injection:** `system()`, `exec()`, backticks, `Open3.capture3()`, `IO.popen()`, `Kernel.open()`
- **SSRF:** `Net::HTTP.get()`, `URI.open()`, `Faraday.get()`, `HTTParty.get()`

### Step 6: Verify Reachability

Before reporting, confirm the code path is actually reachable:

- Is the method called from a route? (check `config/routes/`)
- Is the method behind a `before_action` that might block access?
- Is the code behind a feature flag that is disabled?
- Is the code in a dead branch or deprecated path?

### Step 7: Draft Finding or Log Dead End

- **If taint path is complete:** Draft a candidate finding with full evidence
- **If taint path breaks:** Log as dead end with the specific reason

## Priority Order for Analysis

1. SQL injection (highest impact, most exploitable)
2. Command injection (RCE potential)
3. SSRF (internal network access)
4. XSS (stored > reflected, admin context > user context)

## Anti-Patterns to Watch For

### Rails-Specific Traps

- `order(user_input)` — often overlooked, but allows SQL injection if not validated
- `pluck(user_input)` — same risk as order
- `where("column LIKE '%#{params[:search]}%'")` — classic string interpolation SQLi
- `find_by("name = '#{params[:name]}'")` — string interpolation in finder
- `html_safe` on user-derived content — direct XSS
- `render inline: user_content` — server-side template injection
- `send(params[:method])` — arbitrary method call
- `redirect_to params[:url]` — open redirect / SSRF
- `YAML.load(user_input)` — unsafe deserialization

### Safe Patterns (Not Vulnerable)

- `where(column: value)` — parameterized, safe
- `where("column = ?", value)` — parameterized, safe
- `order(Arel.sql(validated_column))` — safe if validated against allowlist
- `html_safe` on a string literal — safe (no user input)
- `sanitize(user_input)` then use — safe
