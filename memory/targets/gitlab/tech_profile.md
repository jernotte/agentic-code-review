# GitLab CE Technical Profile

- **Version:** ~17.x (tag: 11-10-0cfa69752d8-74ffd66ae-ee-386423-g616404f18500)
- **Commit:** 616404f1850096c3a9a0a057f86584e62c3bbb21
- **Ruby:** 3.3.10
- **Rails:** ~> 7.2.3
- **Grape:** ~> 2.0.0 (REST API framework)
- **GraphQL:** 2.5.11
- **DeclarativePolicy:** ~> 2.0.1 (authorization)
- **Source path:** gitlab-source/

## Key Directories

- `app/controllers/` — Rails controllers (UI + API)
- `app/finders/` — Query builders (high-value for SQLi)
- `app/services/` — Business logic layer
- `app/models/` — ActiveRecord models
- `app/policies/` — DeclarativePolicy authorization rules
- `lib/api/` — Grape REST API endpoints
- `app/graphql/` — GraphQL types, resolvers, mutations
- `config/routes.rb` — Route definitions (includes many sub-files)

## Auth Patterns

- `before_action :authenticate_user!` — Devise auth filter
- `DeclarativePolicy` / `Ability.allowed?` — authorization checks
- Strong Parameters via `params.require(:x).permit(:y)`
- API auth via `lib/api/api_guard.rb`
