# Rails Sources, Sinks, and Sanitizers — Taint Analysis Reference

## SQL Injection

### Sources (User Input Entry Points)
- `params[:key]` / `params.dig(:nested, :key)`
- `params.require(:model).permit(:fields)` — note: Strong Parameters limit which fields pass through
- `request.query_string`
- Cookie values, header values

### Sinks (Dangerous Operations)
- `where("column #{operator} '#{value}'")`  — string interpolation in WHERE
- `where("column = ?", value)` is SAFE; `where("column = '#{value}'")` is NOT
- `find_by_sql("SELECT ... #{user_input} ...")`
- `connection.execute(sql_string)`
- `connection.exec_query(sql_string)`
- `order(user_string)` — allows injection if string not validated
- `group(user_string)` — same risk
- `having(user_string)` — same risk
- `pluck(user_string)` — same risk
- `select(user_string)` — when passed a raw string
- `joins(user_string)` — when passed a raw string
- `from(user_string)` — rarely used but dangerous
- `Arel.sql(user_string)` — wraps raw SQL, dangerous if user-controlled

### Sanitizers / Safe Alternatives
- **Parameterized queries:** `where(column: value)`, `where("col = ?", val)`
- **Type casting:** `.to_i`, `.to_f`, `.to_s` (for integer/float columns)
- **Allowlist:** checking against `%w[name created_at updated_at].include?(sort_column)`
- **`sanitize_sql_like()`** — escapes LIKE wildcards
- **`quote()`** / `connection.quote()` — escapes for SQL strings
- **`sanitize_sql_array()`** — parameterizes array-form SQL
- **Arel API:** `arel_table[:column].eq(value)` — builds safe queries

---

## Cross-Site Scripting (XSS)

### Sources
- `params[:key]` rendered in views
- Database fields populated from user input
- URL components (`request.path`, `request.url`)

### Sinks
- `html_safe` — marks string as safe HTML (bypasses auto-escaping)
- `raw(string)` — same as html_safe
- `content_tag(:tag, user_input, ...)` — safe for content, dangerous for attribute values if not escaped
- `render inline: template_string` — server-side template injection if user-controlled
- `link_to(text, user_url)` — JavaScript URLs (`javascript:alert(1)`) bypass href safety
- ERB `<%= ... %>` auto-escapes; `<%== ... %>` does NOT
- Haml `= expression` auto-escapes; `!= expression` does NOT

### Sanitizers / Safe Alternatives
- **Rails auto-escaping:** `<%= user_input %>` in ERB (default)
- **`sanitize(html_string)`** — allowlist-based HTML sanitizer
- **`strip_tags(string)`** — removes all HTML tags
- **`ERB::Util.html_escape(string)`** / `h(string)` — explicit HTML escaping
- **Content Security Policy** — defense in depth (not a sanitizer per se)

---

## Command Injection

### Sources
- `params[:key]` passed to shell commands
- File names from uploads
- User-provided URLs or paths

### Sinks
- `system(command_string)` — executes in shell when single string arg
- `exec(command_string)` — replaces process
- `` `command_string` `` (backticks) — executes in subshell
- `%x(command_string)` — same as backticks
- `IO.popen(command_string)` — opens pipe to process
- `Open3.capture3(command_string)` — captures stdout/stderr/status
- `Open3.popen3(command_string)` — opens bidirectional pipe
- `Kernel.open(user_string)` — if starts with `|`, executes as command
- `spawn(command_string)` — spawns process

### Sanitizers / Safe Alternatives
- **Array form:** `system("git", "log", user_input)` — no shell interpolation
- **`Shellwords.escape()`** — escapes for shell
- **`Shellwords.shelljoin()`** — joins array safely for shell
- **Allowlist validation** — check command/args against known-safe values

---

## Server-Side Request Forgery (SSRF)

### Sources
- `params[:url]` / `params[:webhook_url]` / `params[:import_url]`
- Webhook configurations stored in DB
- User-provided repository URLs

### Sinks
- `Net::HTTP.get(uri)` / `Net::HTTP.start(host, port)`
- `URI.open(url)` / `Kernel.open(url)` (with http/https URLs)
- `Faraday.get(url)` / `Faraday.new(url:).get(path)`
- `HTTParty.get(url)`
- `RestClient.get(url)`
- `Typhoeus::Request.new(url)`
- `Gitlab::HTTP.get(url)` — GitLab's HTTP wrapper (may have built-in protections)

### Sanitizers / Safe Alternatives
- **`Gitlab::UrlBlocker.validate!(url)`** — GitLab's SSRF protection (blocks internal IPs)
- **`Gitlab::HTTP_V2::UrlBlocker`** — newer version of URL validation
- **Allowlist of domains** — only allow known-safe external domains
- **DNS rebinding protection** — resolve DNS before connecting, verify IP range
- **Block private/internal IPs** — `127.0.0.1`, `10.*`, `172.16-31.*`, `192.168.*`, `::1`, link-local
