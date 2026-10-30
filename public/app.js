'use strict';
// Front-end minimo, sem framework. Todo dado vindo da API e inserido via
// textContent (nunca innerHTML): dominio/docroot vem de servidores remotos e
// sao tratados como nao confiaveis.
(function () {
  const $ = (id) => document.getElementById(id);
  const TOKEN_KEY = 'wpfi.token';
  // Versao minima "atual" usada so para destacar visualmente o que esta velho.
  const WP_BASELINE = '6.5';
  const PHP_BASELINE = '8.1';

  function getToken() {
    try {
      return sessionStorage.getItem(TOKEN_KEY) || '';
    } catch {
      return '';
    }
  }
  function setToken(t) {
    try {
      sessionStorage.setItem(TOKEN_KEY, t);
    } catch {
      /* armazenamento indisponivel: segue so em memoria */
    }
  }

  let token = getToken();

  function headers() {
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  function cmp(a, b) {
    const pa = String(a).split('.').map(Number);
    const pb = String(b).split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0);
      if (d) return Math.sign(d);
    }
    return 0;
  }

  function query() {
    const p = new URLSearchParams();
    if ($('q').value.trim()) p.set('q', $('q').value.trim());
    if ($('status').value) p.set('status', $('status').value);
    if ($('server').value) p.set('server', $('server').value);
    return p;
  }

  function cell(text, cls) {
    const td = document.createElement('td');
    td.textContent = text == null || text === '' ? '-' : String(text);
    if (cls) td.className = cls;
    return td;
  }

  function render(sites) {
    const tbody = $('rows');
    tbody.replaceChildren();
    for (const s of sites) {
      const tr = document.createElement('tr');
      tr.append(
        cell(s.server_label),
        cell(s.account),
        cell(s.domain),
        cell(s.docroot, 'mono'),
        cell(s.wp_version, s.wp_version && cmp(s.wp_version, WP_BASELINE) < 0 ? 'old' : ''),
        cell(s.php_version, s.php_version && cmp(s.php_version, PHP_BASELINE) < 0 ? 'old' : ''),
        cell(s.status, `badge ${s.status}`),
        cell(s.status_detail, 'detail'),
        cell(s.discovery_method),
        cell(s.last_checked_at ? new Date(s.last_checked_at).toLocaleString('pt-BR') : '')
      );
      tbody.append(tr);
    }
    const counts = sites.reduce((acc, s) => ((acc[s.status] = (acc[s.status] || 0) + 1), acc), {});
    $('summary').textContent =
      `${sites.length} instalacao(oes)` +
      (sites.length ? ' - ' + Object.entries(counts).map(([k, v]) => `${k}: ${v}`).join(', ') : '');
  }

  async function api(path) {
    const res = await fetch(path, { headers: headers(), credentials: 'same-origin' });
    if (res.status === 401) throw new Error('nao autenticado');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  }

  async function loadServers() {
    const { servers } = await (await api('/api/servers')).json();
    const sel = $('server');
    sel.length = 1;
    for (const s of servers) sel.add(new Option(s.label, s.label));
  }

  async function load() {
    try {
      const { sites } = await (await api(`/api/sites?${query()}`)).json();
      render(sites);
      $('auth-msg').textContent = '';
    } catch (err) {
      render([]);
      $('auth-msg').textContent = err.message;
    }
  }

  async function exportAs(format) {
    try {
      const p = query();
      p.set('format', format);
      const blob = await (await api(`/api/sites/export?${p}`)).blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `wp-inventory.${format}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    } catch (err) {
      $('auth-msg').textContent = err.message;
    }
  }

  let debounce;
  $('q').addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(load, 250);
  });
  $('status').addEventListener('change', load);
  $('server').addEventListener('change', load);
  $('export-csv').addEventListener('click', () => exportAs('csv'));
  $('export-json').addEventListener('click', () => exportAs('json'));
  $('auth').addEventListener('submit', async (e) => {
    e.preventDefault();
    token = $('token').value.trim();
    setToken(token);
    $('token').value = '';
    await loadServers().catch(() => {});
    load();
  });

  loadServers().catch(() => {});
  load();
})();
