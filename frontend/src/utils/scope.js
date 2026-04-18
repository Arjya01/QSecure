export const defaultScope = {
  scope_key: 'all',
  scope_type: 'all',
  label: 'All Domains',
  domains: [],
  asset_ids: [],
  asset_count: 0,
};

export function getScopeQuery(scope) {
  if (!scope || scope.scope_type === 'all') {
    return '';
  }

  const params = new URLSearchParams();
  if (scope.scope_type === 'group' && scope.id) {
    params.set('group_id', String(scope.id));
  } else if (scope.scope_type === 'domain' && scope.domain) {
    params.set('domain', scope.domain);
  } else if (scope.scope_type === 'asset' && scope.id) {
    params.set('asset_id', String(scope.id));
  }

  const query = params.toString();
  return query ? `?${query}` : '';
}

export function getScopeLabel(scope) {
  return scope?.label || defaultScope.label;
}

export function scopeContainsDomain(scope, domain) {
  if (!scope || scope.scope_type === 'all' || !domain) {
    return false;
  }
  if (scope.scope_type === 'domain') {
    return scope.domain === domain;
  }
  return (scope.domains || []).includes(domain);
}
