# Research Terms — Taint Analysis

Domain terminology organized by vulnerability sub-class. These terms focus agent attention on relevant code patterns during analysis.

## SQL Injection

ActiveRecord, string interpolation, where, find_by, find_by_sql, sanitize_sql,
sanitize_sql_like, sanitize_sql_array, Arel, arel_table, pluck, order, group,
having, joins, select, from, connection.execute, exec_query, quoted_table_name,
params, cookies, request.env, Strong Parameters, permit, require, to_i, to_f,
quote, parameterized query, bind variable, prepared statement

## Cross-Site Scripting (XSS)

html_safe, raw, content_tag, render inline, ERB, Haml, sanitize, strip_tags,
SafeBuffer, ActionView, html_escape, h(), auto-escape, <%==, !=, link_to,
javascript: URI, data: URI, content_security_policy, CSP, dom-based

## Command Injection

system, exec, backtick, Open3, IO.popen, Kernel.open, spawn, %x,
Shellwords.escape, shelljoin, shell metacharacter, pipe character,
semicolon, ampersand, subshell, process.spawn, capture3, popen3

## Server-Side Request Forgery (SSRF)

Net::HTTP, open-uri, URI.open, Faraday, HTTParty, RestClient, Typhoeus,
Gitlab::HTTP, UrlBlocker, validate!, internal IP, private IP, DNS rebinding,
webhook, import_url, repository URL, redirect follow, TOCTOU,
127.0.0.1, 169.254, metadata endpoint, cloud IMDS

## GitLab-Specific Terms

DeclarativePolicy, Ability.allowed?, before_action, authenticate_user!,
authorize_read, authorize_admin, feature_flag, Feature.enabled?,
Grape API, grape endpoint, helpers, present, Gitaly, Workhorse,
ProjectsFinder, IssuesFinder, MergeRequestsFinder, GroupsFinder,
app/finders, app/services, lib/api, app/graphql
