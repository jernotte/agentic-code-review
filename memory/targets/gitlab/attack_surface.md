# GitLab CE Attack Surface

Generated: 2026-03-13 06:19 UTC

## Summary

- **Controllers:** 387
- **API endpoints:** 875
- **Finders with SQL risk patterns:** 178
- **Controllers with weakened auth:** 0
- **Controllers handling file uploads:** 46

## Priority 1: Finders with SQL Risk Patterns

These files construct database queries and show patterns that may indicate SQL injection risk.

- **app/finders/packages/build_infos_finder.rb** (risk: 10) — string interpolation, raw SQL, uses params
- **app/finders/ci/build_source_finder.rb** (risk: 8) — string interpolation, string WHERE, uses params
- **app/finders/personal_access_tokens_finder.rb** (risk: 6) — string interpolation, uses params
- **app/finders/members_finder.rb** (risk: 6) — string interpolation, uses params
- **app/finders/ci/pipelines_finder.rb** (risk: 6) — string interpolation, uses params
- **app/finders/releases/group_releases_finder.rb** (risk: 6) — string interpolation, uses params
- **app/finders/group_members_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/branches_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/tags_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/releases_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/notes_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/deployments_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/issuable_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/ci/runners_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/ci/group_variables_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/ci/jobs_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/work_items/work_items_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/concerns/custom_attributes_filter.rb** (risk: 5) — string WHERE, uses params
- **app/finders/projects/ml/model_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/projects/ml/experiment_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/projects/ml/candidate_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/projects/ml/model_version_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/packages/packages_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/packages/debian/distributions_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/issuable_finder/params.rb** (risk: 5) — string interpolation, uses params
- **app/finders/security/jobs_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/autocomplete/group_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/autocomplete/project_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/timelogs/timelogs_finder.rb** (risk: 5) — string interpolation, uses params
- **app/finders/groups_finder.rb** (risk: 4) — string WHERE, uses params

## Priority 2: High-Value Controllers

- **app/controllers/uploads_controller.rb** [UploadsController] (score: 24) — skips: check_two_factor_requirement, file upload, params
- **app/controllers/projects_controller.rb** [ProjectsController] (score: 21) — skips: enforce_step_up_auth_for_namespace, file upload, params
- **app/controllers/groups_controller.rb** [GroupsController] (score: 21) — skips: enforce_step_up_auth_for_namespace, file upload, params
- **app/controllers/projects/merge_requests_controller.rb** [Projects::MergeRequestsController] (score: 21) — skips: merge_request, file upload, params
- **app/controllers/projects/issues_controller.rb** [Projects::IssuesController] (score: 21) — file upload, params
- **app/controllers/projects/pipelines_controller.rb** [Projects::PipelinesController] (score: 21) — file upload, params
- **app/controllers/projects/blob_controller.rb** [Projects::BlobController] (score: 20) — file upload, params
- **app/controllers/user_settings/passwords_controller.rb** [PasswordsController] (score: 20) — skips: check_password_expiration,check_two_factor_requirement,active_user_check, params
- **app/controllers/repositories/lfs_locks_api_controller.rb** [LfsLocksApiController] (score: 20) — file upload, params, API
- **app/controllers/projects/jobs_controller.rb** [Projects::JobsController] (score: 18) — file upload, params
- **app/controllers/projects/merge_requests/creations_controller.rb** [Projects::MergeRequests::CreationsController] (score: 18) — skips: merge_request, file upload, params
- **app/controllers/admin/application_settings_controller.rb** [ApplicationSettingsController] (score: 18) — file upload, params
- **app/controllers/admin/topics_controller.rb** [Admin::TopicsController] (score: 18) — file upload, params
- **app/controllers/repositories/lfs_api_controller.rb** [LfsApiController] (score: 18) — file upload, params, API
- **app/controllers/sessions_controller.rb** [SessionsController] (score: 17) — skips: check_two_factor_requirement,check_password_expiration, params
- **app/controllers/help_controller.rb** [HelpController] (score: 17) — skips: check_two_factor_requirement, file upload, params
- **app/controllers/projects/artifacts_controller.rb** [Projects::ArtifactsController] (score: 17) — file upload, params
- **app/controllers/projects/uploads_controller.rb** [Projects::UploadsController] (score: 17) — skips: project,enforce_step_up_auth_for_namespace, file upload, params
- **app/controllers/groups/dependency_proxy_for_containers_controller.rb** [Groups::DependencyProxyForContainersController] (score: 17) — skips: verify_authenticity_token, file upload, params
- **app/controllers/groups/uploads_controller.rb** [Groups::UploadsController] (score: 17) — skips: group,enforce_step_up_auth_for_namespace, file upload, params
- **app/controllers/admin/users_controller.rb** [Admin::UsersController] (score: 16) — params
- **app/controllers/import/github_controller.rb** [Import::GithubController] (score: 16) — params
- **app/controllers/application_controller.rb** [ApplicationController] (score: 15) — file upload, params
- **app/controllers/graphql_controller.rb** [GraphqlController] (score: 15) — skips: active_user_check,verify_authenticity_token,check_two_factor_requirement, params
- **app/controllers/projects/commit_controller.rb** [Projects::CommitController] (score: 15) — params
- **app/controllers/projects/work_items_controller.rb** [Projects::WorkItemsController] (score: 15) — file upload, params
- **app/controllers/projects/settings/repository_controller.rb** [RepositoryController] (score: 15) — file upload, params
- **app/controllers/admin/applications_controller.rb** [Admin::ApplicationsController] (score: 15) — params
- **app/controllers/users/terms_controller.rb** [TermsController] (score: 15) — skips: check_password_expiration,check_two_factor_requirement,require_email, params
- **app/controllers/import/manifest_controller.rb** [Import::ManifestController] (score: 15) — file upload, params

## Priority 4: File Upload Handlers

- **app/controllers/uploads_controller.rb** [UploadsController]
- **app/controllers/projects_controller.rb** [ProjectsController]
- **app/controllers/groups_controller.rb** [GroupsController]
- **app/controllers/projects/merge_requests_controller.rb** [Projects::MergeRequestsController]
- **app/controllers/projects/issues_controller.rb** [Projects::IssuesController]
- **app/controllers/projects/pipelines_controller.rb** [Projects::PipelinesController]
- **app/controllers/projects/blob_controller.rb** [Projects::BlobController]
- **app/controllers/repositories/lfs_locks_api_controller.rb** [LfsLocksApiController]
- **app/controllers/projects/jobs_controller.rb** [Projects::JobsController]
- **app/controllers/projects/merge_requests/creations_controller.rb** [Projects::MergeRequests::CreationsController]
- **app/controllers/admin/application_settings_controller.rb** [ApplicationSettingsController]
- **app/controllers/admin/topics_controller.rb** [Admin::TopicsController]
- **app/controllers/repositories/lfs_api_controller.rb** [LfsApiController]
- **app/controllers/help_controller.rb** [HelpController]
- **app/controllers/projects/artifacts_controller.rb** [Projects::ArtifactsController]
- **app/controllers/projects/uploads_controller.rb** [Projects::UploadsController]
- **app/controllers/groups/dependency_proxy_for_containers_controller.rb** [Groups::DependencyProxyForContainersController]
- **app/controllers/groups/uploads_controller.rb** [Groups::UploadsController]
- **app/controllers/application_controller.rb** [ApplicationController]
- **app/controllers/projects/work_items_controller.rb** [Projects::WorkItemsController]
- **app/controllers/projects/settings/repository_controller.rb** [RepositoryController]
- **app/controllers/import/manifest_controller.rb** [Import::ManifestController]
- **app/controllers/projects/settings/ci_cd_controller.rb** [CiCdController]
- **app/controllers/banzai/uploads_controller.rb** [UploadsController]
- **app/controllers/projects/build_artifacts_controller.rb** [Projects::BuildArtifactsController]
- **app/controllers/projects/merge_requests/diffs_controller.rb** [Projects::MergeRequests::DiffsController]
- **app/controllers/import/gitlab_projects_controller.rb** [Import::GitlabProjectsController]
- **app/controllers/repositories/git_http_controller.rb** [GitHttpController]
- **app/controllers/import/gitlab_groups_controller.rb** [Import::GitlabGroupsController]
- **app/controllers/repositories/git_http_client_controller.rb** [GitHttpClientController]
- **app/controllers/projects/releases_controller.rb** [Projects::ReleasesController]
- **app/controllers/projects/attestations_controller.rb** [AttestationsController]
- **app/controllers/projects/ml/experiments_controller.rb** [ExperimentsController]
- **app/controllers/projects/merge_requests/conflicts_controller.rb** [Projects::MergeRequests::ConflictsController]
- **app/controllers/repositories/lfs_storage_controller.rb** [LfsStorageController]
- **app/controllers/projects/tree_controller.rb** [Projects::TreeController]
- **app/controllers/projects/repositories_controller.rb** [Projects::RepositoriesController]
- **app/controllers/groups/bulk_placeholder_assignments_controller.rb** [BulkPlaceholderAssignmentsController]
- **app/controllers/projects/web_ide_schemas_controller.rb** [Projects::WebIdeSchemasController]
- **app/controllers/projects/ci/daily_build_group_report_results_controller.rb** [Projects::Ci::DailyBuildGroupReportResultsController]
- **app/controllers/projects/packages/package_files_controller.rb** [PackageFilesController]
- **app/controllers/projects/design_management/designs/resized_image_controller.rb** [ResizedImageController]
- **app/controllers/activity_pub/projects/application_controller.rb** [ApplicationController]
- **app/controllers/projects/clusters_controller.rb** [Projects::ClustersController]
- **app/controllers/projects/application_controller.rb** [Projects::ApplicationController]
- **app/controllers/jira_connect/app_descriptor_controller.rb** [JiraConnect::AppDescriptorController]

## API Endpoints (Top 30 by Priority)

- `POST :id/merge_requests/:merge_request_iid/context_commits` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid/commits` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid/context_commits` (lib/api/merge_requests.rb) [NO AUTH]
- `DELETE :id/merge_requests/:merge_request_iid/context_commits` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid/raw_diffs` (lib/api/merge_requests.rb) [NO AUTH]
- `POST :id/archive` (lib/api/projects.rb) [NO AUTH]
- `POST :id/unarchive` (lib/api/projects.rb) [NO AUTH]
- `POST :id/import_project_members/:project_id` (lib/api/projects.rb) [NO AUTH]
- `POST :id/archive` (lib/api/groups.rb) [NO AUTH]
- `POST :id/unarchive` (lib/api/groups.rb) [NO AUTH]
- `POST :id/merge_requests` (lib/api/merge_requests.rb) [NO AUTH]
- `POST :id/merge_requests/:merge_request_iid/pipelines` (lib/api/merge_requests.rb) [NO AUTH]
- `PUT :id/merge_requests/:merge_request_iid` (lib/api/merge_requests.rb) [NO AUTH]
- `PUT :id/merge_requests/:merge_request_iid/merge` (lib/api/merge_requests.rb) [NO AUTH]
- `POST :id/merge_requests/:merge_request_iid/cancel_merge_when_pipeline_succeeds` (lib/api/merge_requests.rb) [NO AUTH]
- `PUT :id/merge_requests/:merge_request_iid/rebase` (lib/api/merge_requests.rb) [NO AUTH]
- `POST :id/reset_authentication_token` (lib/api/ci/runners.rb) [NO AUTH]
- `POST reset_registration_token` (lib/api/ci/runners.rb) [NO AUTH]
- `POST :id/runners/reset_registration_token` (lib/api/ci/runners.rb) [NO AUTH]
- `POST :id/runners/reset_registration_token` (lib/api/ci/runners.rb) [NO AUTH]
- `POST :id/access_tokens/self/rotate` (lib/api/resource_access_tokens/self_rotation.rb) [NO AUTH]
- `GET :id/merge_requests` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests` (lib/api/merge_requests.rb) [NO AUTH]
- `DELETE :id/merge_requests/:merge_request_iid` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid/participants` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid/reviewers` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid/changes` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid/diffs` (lib/api/merge_requests.rb) [NO AUTH]
- `GET :id/merge_requests/:merge_request_iid/pipelines` (lib/api/merge_requests.rb) [NO AUTH]

