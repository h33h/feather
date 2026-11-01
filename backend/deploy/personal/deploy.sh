#!/usr/bin/env bash
set -euo pipefail

# Called over SSH with the existing Compose directory, image archive and expected commit SHA.
if [[ $# != 3 || ! "$3" =~ ^[a-f0-9]{40}$ ]]; then
  echo 'Usage: deploy.sh COMPOSE_DIRECTORY IMAGE_ARCHIVE COMMIT_SHA' >&2
  exit 2
fi
project="$1"
archive="$2"
commit="$3"
cd "$project"
test -f compose.yml
test -f .env
test -f "$archive"
# Also serialize operator invocations on the server.
exec 9>.deploy.lock
flock -w 120 9
unset WEB_IMAGE

candidate=''
candidate_compose=''
known_images="$(docker image ls --no-trunc --format '{{.ID}} {{.ID}}' isign-web)"
cleanup() {
  [[ -z "$candidate" ]] || rm -f -- "$candidate"
  [[ -z "$candidate_compose" ]] || rm -f -- "$candidate_compose"
  local images tag id containers
  if ! images="$(docker image ls --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}' isign-web)"; then
    echo 'Could not list web images for cleanup.' >&2
    return 0
  fi
  # A repeated build of the same commit can displace a tag during docker load.
  # Include pre-load IDs so those newly dangling images are removed as well.
  images+=$'\n'"$known_images"
  while read -r tag id; do
    [[ -n "$id" ]] || continue
    docker image inspect "$tag" >/dev/null 2>&1 || continue
    if [[ "$tag" == "$id" ]]; then
      # Remove snapshot IDs only when untagged; other repositories may share them.
      [[ "$(docker image inspect "$id" --format '{{len .RepoTags}}')" == 0 ]] || continue
    fi
    if ! containers="$(docker ps --all --quiet --filter "ancestor=$id")"; then
      echo "Could not check containers using $tag; skipping cleanup." >&2
      continue
    fi
    if [[ -z "$containers" ]]; then
      docker image rm "$tag" || echo "Could not remove unused web image $tag." >&2
    fi
  done <<< "$images"
}
# Clean up after success or failure, after the failed service is stopped.
# Keep only images referenced by containers, without reserving a previous version.
trap cleanup EXIT
docker load --input "$archive"
# Docker image IDs can differ between containerd and classic image stores.
# Resolve the immutable ID on this daemon after checking the commit label.
tag="isign-web:$commit"
revision="$(docker image inspect "$tag" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
if [[ "$revision" != "$commit" ]]; then
  echo 'Loaded image commit label does not match the deployment commit.' >&2
  exit 1
fi
image="$(docker image inspect "$tag" --format '{{.Id}}')"
[[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]]
candidate="$(mktemp .env.deploy.XXXXXX)"
awk '!/^[[:space:]]*(export[[:space:]]+)?WEB_IMAGE[[:space:]]*=/' .env > "$candidate"
printf 'WEB_IMAGE=%s\n' "$image" >> "$candidate"
chmod 600 "$candidate"

# Existing servers retain their operator-owned Compose file between deployments.
# Migrate only the two exact legacy runtime paths in a private candidate copy.
candidate_compose="$(mktemp compose.deploy.XXXXXX.yml)"
sed -E \
  -e 's@(^|[^[:alnum:]_/.-])scripts/personal-start\.ts([^[:alnum:]_/.-]|$)@\1backend/scripts/personal-start.ts\2@g' \
  -e 's@/app/apps/web/\.next/cache([^[:alnum:]_/.-]|$)@/app/web/.next/cache\1@g' \
  compose.yml > "$candidate_compose"
chmod 600 "$candidate_compose"

next_compose=(docker compose --env-file "$candidate" -f "$candidate_compose")
"${next_compose[@]}" config --quiet
check_readiness() {
  local host
  host="$("${next_compose[@]}" exec -T web node -p 'new URL(process.env.ISIGN_ORIGIN).host')" || return 1
  [[ "$host" =~ ^[a-zA-Z0-9.-]+(:[0-9]+)?$ ]] || return 1
  curl --fail --silent --show-error --retry 12 --retry-delay 5 --retry-all-errors \
    --retry-max-time 120 --max-time 70 --header "Host: $host" --output /dev/null http://127.0.0.1:3080/api/health
}
if "${next_compose[@]}" up --no-deps --detach --pull never --wait --wait-timeout 120 web &&
  check_readiness; then
  mv -f -- "$candidate_compose" compose.yml
  mv -f -- "$candidate" .env
  printf 'Deployed web image %s\n' "$image"
else
  echo 'Deployment failed; .env retains the previous image.' >&2
  "${next_compose[@]}" stop web || echo 'Could not stop failed web; operator intervention required.' >&2
  exit 1
fi
