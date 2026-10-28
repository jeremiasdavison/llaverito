// Llaverito UI. Sin dependencias ni paso de build. Todo el contenido dinámico se inserta con
// textContent (helper `h`), nunca con innerHTML, para evitar XSS desde nombres de credenciales.

const $app = document.getElementById('app');
const state = { user: null, folders: [], folderId: null, pending: 0, timer: null };

// ------------------------------------------------------------------ utilidades

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove('show'), 2600);
}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch('/api' + path, {
    method,
    credentials: 'same-origin',
    headers: { 'X-Requested-With': 'llaverito', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && path !== '/auth/login' && state.user) {
      state.user = null;
      render();
    }
    const d = data.detail;
    throw new Error(Array.isArray(d) ? d.map((e) => e.msg).join('; ') : d || `Error ${res.status}`);
  }
  return data;
}

function modal(title, content, actions = []) {
  const bg = h('div', { class: 'modal-bg' });
  const close = () => bg.remove();
  const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' }, h('h2', null, title), content,
    actions.length ? h('div', { class: 'actions' }, actions.map((a) => {
      const b = h('button', { class: `btn ${a.cls || ''}`, type: 'button' }, a.label);
      b.addEventListener('click', async () => {
        b.disabled = true;
        try { if ((await a.run(close)) !== false && a.close !== false) close(); }
        catch (e) { showError(box, e.message); }
        finally { b.disabled = false; }
      });
      return b;
    })) : null);
  bg.append(box);
  bg.addEventListener('mousedown', (e) => { if (e.target === bg) close(); });
  document.body.append(bg);
  return close;
}

function showError(box, msg) {
  box.querySelector('.error')?.remove();
  const actions = box.querySelector('.actions');
  box.insertBefore(h('div', { class: 'error' }, msg), actions);
}

const fmt = (iso) => (iso ? new Date(iso).toLocaleString('es-AR') : '—');
const copy = async (text) => { await navigator.clipboard.writeText(text); toast('Copiado'); };
const SHARED = '__shared__';
const DURATIONS = [['15 minutos', 15], ['1 hora', 60], ['8 horas', 480], ['24 horas', 1440], ['7 días', 10080], ['30 días', 43200], ['Permanente', null]];
function until(iso) {
  const mins = Math.round((new Date(iso) - Date.now()) / 60000);
  if (mins <= 0) return 'vencida';
  if (mins < 60) return `vence en ${mins} min`;
  if (mins < 1440) return `vence en ${Math.round(mins / 60)} h`;
  return `vence en ${Math.round(mins / 1440)} d`;
}
const linesOf = (s) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', null, label), input, hint ? h('div', { class: 'hint' }, hint) : null);
}
const check = (label, checked) => {
  const input = h('input', { type: 'checkbox', checked });
  return { input, node: h('label', { class: 'check' }, input, label) };
};

// ------------------------------------------------------------------ tipos de credencial

const TYPES = {
  bearer_token: { label: 'Token Bearer', http: true, mode: 'bearer', secret: [['secret', 'Token']] },
  api_key: { label: 'API key', http: true, mode: 'header', secret: [['secret', 'API key']] },
  basic_auth: { label: 'Usuario y contraseña (HTTP Basic)', http: true, mode: 'basic', secret: [['password', 'Contraseña']] },
  password: { label: 'Contraseña (solo vía placeholders)', http: true, mode: 'none', secret: [['password', 'Contraseña']] },
  ssh_password: { label: 'SSH con contraseña', ssh: true, secret: [['password', 'Contraseña']] },
  ssh_key: { label: 'SSH con clave privada', ssh: true, secret: [['private_key', 'Clave privada (PEM)', true], ['passphrase', 'Passphrase (opcional)']] },
};
const MODES = { bearer: 'Authorization: Bearer', header: 'Cabecera personalizada', basic: 'Authorization: Basic', query: 'Parámetro de query', none: 'Ninguno (solo placeholders)' };

function credentialForm(existing) {
  const writable = state.folders.filter((f) => f.level === 'write');
  const meta = existing?.meta || {};
  const f = {};
  f.folder = h('select', { disabled: !!existing }, writable.map((x) => h('option', { value: x.id, selected: (existing?.folder_id || state.folderId) === x.id }, x.name)));
  f.name = h('input', { type: 'text', value: existing?.name || '' });
  f.type = h('select', { disabled: !!existing }, Object.entries(TYPES).map(([k, v]) => h('option', { value: k, selected: existing?.type === k }, v.label)));
  f.desc = h('input', { type: 'text', value: meta.description || '' });
  f.sensitive = check('Sensible: cada uso requiere aprobación humana', existing?.sensitive);
  f.reveal = check('Permitir que personas revelen el valor (los agentes nunca lo ven)', existing ? existing.allow_reveal : true);
  const dyn = h('div');
  const inputs = {};

  const drawDynamic = () => {
    const t = TYPES[f.type.value];
    dyn.replaceChildren();
    Object.keys(inputs).forEach((k) => delete inputs[k]);
    if (t.http) {
      inputs.hosts = h('textarea', { placeholder: 'api.example.com\n*.example.com' }, (meta.allowed_hosts || []).join('\n'));
      inputs.mode = h('select', null, Object.entries(MODES).map(([k, v]) => h('option', { value: k, selected: (meta.inject_mode || t.mode) === k }, v)));
      inputs.header = h('input', { type: 'text', value: meta.header_name || 'X-API-Key' });
      inputs.qparam = h('input', { type: 'text', value: meta.query_param || 'api_key' });
      inputs.user = h('input', { type: 'text', value: meta.username || '' });
      inputs.http = check('Permitir HTTP sin TLS', meta.allow_http);
      inputs.priv = check('Permitir destinos en red privada (servicios internos)', meta.allow_private_network);
      dyn.append(
        field('Hosts permitidos (uno por línea)', inputs.hosts, 'Obligatorio. El agente solo podrá usar esta credencial contra estos hosts.'),
        field('Cómo se inyecta la autenticación', inputs.mode),
        field('Nombre de cabecera (modo cabecera)', inputs.header),
        field('Parámetro de query (modo query)', inputs.qparam),
        field('Usuario (Basic / {{username}})', inputs.user),
        inputs.http.node, inputs.priv.node,
      );
    } else {
      inputs.host = h('input', { type: 'text', value: meta.host || '' });
      inputs.port = h('input', { type: 'number', value: meta.port || 22, min: 1, max: 65535 });
      inputs.user = h('input', { type: 'text', value: meta.username || '' });
      inputs.cmds = h('textarea', { placeholder: 'uptime\nsystemctl status *' }, (meta.allowed_commands || []).join('\n'));
      dyn.append(
        field('Host', inputs.host), field('Puerto', inputs.port), field('Usuario', inputs.user),
        field('Comandos que no requieren aprobación (uno por línea)', inputs.cmds,
          'Los comodines no cubren metacaracteres de shell (; | & $ ...). Vacío = todo comando pide aprobación.'),
      );
    }
    for (const [name, label, area] of t.secret) {
      inputs['s_' + name] = area ? h('textarea', { placeholder: existing ? '(sin cambios)' : '' }) : h('input', { type: 'password', autocomplete: 'new-password', placeholder: existing ? '(sin cambios)' : '' });
      dyn.append(field(existing ? `${label} — dejar vacío para no cambiar` : label, inputs['s_' + name]));
    }
  };
  f.type.addEventListener('change', drawDynamic);
  drawDynamic();

  const collect = () => {
    const t = TYPES[f.type.value];
    let m = { description: f.desc.value.trim() };
    if (t.http) {
      m = { ...m, allowed_hosts: linesOf(inputs.hosts.value), inject_mode: inputs.mode.value, header_name: inputs.header.value.trim() || 'X-API-Key',
        query_param: inputs.qparam.value.trim() || 'api_key', username: inputs.user.value.trim(), allow_http: inputs.http.input.checked,
        allow_private_network: inputs.priv.input.checked };
    } else {
      m = { ...m, host: inputs.host.value.trim(), port: Number(inputs.port.value) || 22, username: inputs.user.value.trim(), allowed_commands: linesOf(inputs.cmds.value) };
      if (existing) m.host_key = meta.host_key || '';
    }
    const secret = {};
    for (const [name] of t.secret) { const v = inputs['s_' + name].value; if (v) secret[name] = v; }
    return { meta: m, secret };
  };

  const node = h('div', null,
    field('Carpeta', f.folder), field('Nombre', f.name), field('Tipo', f.type), field('Descripción', f.desc),
    dyn, f.sensitive.node, f.reveal.node);
  return { node, f, collect };
}

// ------------------------------------------------------------------ vistas: credenciales

async function viewCredentials(root) {
  state.folders = await api('/folders');
  if (state.folderId !== SHARED && !state.folders.some((x) => x.id === state.folderId)) state.folderId = null;
  const query = h('input', { type: 'search', placeholder: 'Buscar…' });
  const tbody = h('tbody');
  const list = h('div');
  const side = h('div', { class: 'panel side' });

  const load = async () => {
    const qs = new URLSearchParams();
    if (state.folderId === SHARED) qs.set('shared', 'true');
    else if (state.folderId) qs.set('folder_id', state.folderId);
    if (query.value) qs.set('q', query.value);
    const creds = await api('/credentials?' + qs);
    tbody.replaceChildren(...creds.map((c) => h('tr', { class: 'click', onclick: () => detail(c) },
      h('td', null, h('strong', null, c.name), h('div', { class: 'muted small' }, c.meta.description || '')),
      h('td', null, c.folder), h('td', null, h('span', { class: 'tag' }, TYPES[c.type]?.label || c.type), c.sensitive ? h('span', { class: 'tag pending' }, 'sensible') : null,
        c.access === 'shared' ? h('span', { class: 'tag' }, c.shared_permanent ? 'compartida · permanente' : `compartida · ${until(c.shared_until)}`) : null),
      h('td', { class: 'mono' }, c.ref))));
    list.replaceChildren(creds.length ? h('table', null, h('thead', null, h('tr', null, ['Nombre', 'Carpeta', 'Tipo', 'Referencia para agentes'].map((x) => h('th', null, x)))), tbody)
      : h('div', { class: 'empty' }, state.folders.length || state.folderId === SHARED ? 'No hay credenciales para mostrar.' : 'No tenés acceso a ninguna carpeta todavía. Pedile a un administrador que cree o te comparta una.'));
  };

  const drawSide = () => {
    side.replaceChildren(
      h('button', { class: `folder ${state.folderId ? '' : 'active'}`, onclick: () => { state.folderId = null; drawSide(); load(); } }, 'Todas'),
      h('button', { class: `folder ${state.folderId === SHARED ? 'active' : ''}`, onclick: () => { state.folderId = SHARED; drawSide(); load(); } }, 'Compartidas conmigo'),
      ...state.folders.map((fo) => h('button', { class: `folder ${state.folderId === fo.id ? 'active' : ''}`, onclick: () => { state.folderId = fo.id; drawSide(); load(); } }, fo.name)));
  };

  const create = () => {
    if (!state.folders.some((x) => x.level === 'write')) return toast('No tenés carpetas con permiso de escritura');
    const form = credentialForm();
    modal('Nueva credencial', form.node, [
      { label: 'Cancelar', run: () => true },
      { label: 'Guardar', cls: 'primary', run: async () => {
        const { meta, secret } = form.collect();
        await api('/credentials', { method: 'POST', body: { folder_id: form.f.folder.value, name: form.f.name.value, type: form.f.type.value, meta, secret,
          sensitive: form.f.sensitive.input.checked, allow_reveal: form.f.reveal.input.checked } });
        toast('Credencial creada'); load();
      } },
    ]);
  };

  query.addEventListener('input', () => { clearTimeout(query.t); query.t = setTimeout(load, 250); });
  drawSide();
  root.append(h('div', { class: 'row between' }, h('h1', null, 'Credenciales'), h('button', { class: 'btn primary', onclick: create }, '+ Nueva credencial')),
    h('div', { class: 'layout' }, side, h('div', { class: 'panel' }, h('div', { class: 'row' }, h('div', { class: 'grow' }, query)), list)));
  await load();

  function detail(c) {
    const meta = c.meta;
    const rows = [['Referencia', h('code', null, c.ref)], ['Tipo', TYPES[c.type]?.label || c.type], ['Descripción', meta.description || '—']];
    if (TYPES[c.type]?.http) {
      rows.push(['Hosts permitidos', (meta.allowed_hosts || []).join(', ') || '— (ninguno: los agentes no podrán usarla)'], ['Inyección', MODES[meta.inject_mode]],
        ['Red privada', meta.allow_private_network ? 'Sí' : 'No']);
    } else {
      rows.push(['Destino', `${meta.username}@${meta.host}:${meta.port}`], ['Comandos sin aprobación', (meta.allowed_commands || []).join(' · ') || '— (todos piden aprobación)'],
        ['Clave del host', meta.host_key ? h('span', { class: 'tag ok' }, 'fijada') : h('span', { class: 'tag denied' }, 'sin fijar — los agentes no pueden usarla')]);
    }
    rows.push(['Sensible', c.sensitive ? 'Sí (aprobación en cada uso)' : 'No'], ['Versión', c.version], ['Actualizada', fmt(c.updated_at)]);
    const shared = c.access === 'shared';
    if (shared) {
      rows.push(['Compartida contigo', `${c.share_level === 'reveal' ? 'Podés usarla y ver el valor' : 'Podés usarla con tus agentes (no ver el valor)'} · ${c.shared_permanent ? 'permanente' : 'vence ' + fmt(c.shared_until)}`]);
    }
    const body = h('dl', { class: 'kv' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
    const actions = [{ label: 'Cerrar', run: () => true }];
    const canReveal = c.allow_reveal && (shared ? c.share_level === 'reveal' : state.user.role !== 'viewer');
    if (canReveal) actions.push({ label: 'Revelar…', close: false, run: (close) => { close(); reveal(c); return false; } });
    if (c.can_write) {
      actions.push({ label: 'Compartir…', close: false, run: (close) => { close(); shareDialog(c); return false; } });
      if (!TYPES[c.type]?.http) actions.push({ label: 'Fijar clave del host…', close: false, run: (close) => { close(); pinHostKey(c); return false; } });
      actions.push({ label: 'Editar', close: false, run: (close) => { close(); edit(c); return false; } });
      actions.push({ label: 'Eliminar', cls: 'danger', run: async () => {
        if (!confirm(`¿Eliminar "${c.name}"? Los agentes con acceso lo perderán.`)) return false;
        await api('/credentials/' + c.id, { method: 'DELETE' }); toast('Eliminada'); load();
      } });
    }
    modal(c.name, body, actions);
  }

  async function shareDialog(c) {
    let people;
    try { people = await api('/users/directory'); } catch (e) { return toast(e.message); }
    const content = h('div');
    const person = h('select', null, people.map((p) => h('option', { value: p.id }, `${p.name} · ${p.email}`)));
    const level = h('select', null,
      h('option', { value: 'reveal' }, 'Usar y ver el valor'),
      h('option', { value: 'use' }, 'Solo usar con sus agentes (no ve el valor)'));
    const duration = h('select', null, DURATIONS.map(([label, minutes]) => h('option', { value: minutes ?? '' }, label)));
    const drawCurrent = async () => {
      const shares = await api(`/credentials/${c.id}/shares`);
      const remove = async (s) => { await api(`/credentials/${c.id}/shares/${s.id}`, { method: 'DELETE' }); toast('Se dejó de compartir'); drawCurrent(); load(); };
      current.replaceChildren(shares.length ? h('div', null, ...shares.map((s) => h('div', { class: 'row between card' },
        h('div', null, h('strong', null, s.name), h('div', { class: 'muted small' }, `${s.email} · ${s.level === 'reveal' ? 'usa y ve' : 'solo usa'}`)),
        h('div', { class: 'row' },
          s.expired ? h('span', { class: 'tag denied' }, 'vencida') : h('span', { class: 'tag' }, s.permanent ? 'permanente' : until(s.expires_at)),
          h('button', { class: 'btn small danger', onclick: () => remove(s) }, 'Quitar'))))) : h('div', { class: 'muted small' }, 'Todavía no está compartida con nadie.'));
    };
    const current = h('div');
    const add = async () => {
      if (!people.length) return toast('No hay otras personas activas');
      await api(`/credentials/${c.id}/shares`, { method: 'POST', body: { user_id: person.value, level: level.value, expires_in_minutes: duration.value ? Number(duration.value) : null } });
      toast('Compartida'); drawCurrent(); load();
    };
    content.append(
      h('p', { class: 'muted small' }, 'La persona tiene que haber ingresado a Llaverito al menos una vez. Si ya tiene la carpeta, no hace falta compartir. Todo queda auditado.'),
      field('Persona', person), field('Qué puede hacer', level), field('Por cuánto tiempo', duration),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'button', onclick: () => add().catch((e) => toast(e.message)) }, 'Compartir')),
      h('h2', null, 'Compartida con'), current);
    modal(`Compartir "${c.name}"`, content, [{ label: 'Cerrar', run: () => true }]);
    drawCurrent();
  }

  function edit(c) {
    const form = credentialForm(c);
    modal('Editar credencial', form.node, [
      { label: 'Cancelar', run: () => true },
      { label: 'Guardar', cls: 'primary', run: async () => {
        const { meta, secret } = form.collect();
        const body = { name: form.f.name.value, meta, sensitive: form.f.sensitive.input.checked, allow_reveal: form.f.reveal.input.checked };
        if (Object.keys(secret).length) body.secret = secret;
        await api('/credentials/' + c.id, { method: 'PATCH', body }); toast('Guardada'); load();
      } },
    ]);
  }

  function reveal(c) {
    const pw = h('input', { type: 'password', autocomplete: 'current-password' });
    modal('Revelar secreto', h('div', null, h('p', { class: 'muted' }, 'Por seguridad, confirmá tu contraseña. Esta acción queda auditada.'), field('Tu contraseña', pw)), [
      { label: 'Cancelar', run: () => true },
      { label: 'Revelar', cls: 'primary', close: false, run: async (close) => {
        const { secret } = await api(`/credentials/${c.id}/reveal`, { method: 'POST', body: { password: pw.value } });
        close();
        const blocks = Object.entries(secret).map(([k, v]) => h('div', null, h('div', { class: 'muted small' }, k), h('pre', { class: 'code' }, v), h('button', { class: 'btn small', onclick: () => copy(v) }, 'Copiar')));
        const closeSecret = modal(`Secreto de ${c.name}`, h('div', null, blocks, h('p', { class: 'hint' }, 'Se oculta solo en 30 segundos.')), [{ label: 'Cerrar', run: () => true }]);
        setTimeout(closeSecret, 30000);
        return false;
      } },
    ]);
    setTimeout(() => pw.focus(), 50);
  }

  async function pinHostKey(c) {
    let scan;
    try { scan = await api(`/credentials/${c.id}/scan-host-key`, { method: 'POST' }); } catch (e) { return toast(e.message); }
    const same = scan.current && scan.current.split(' ')[1] === scan.host_key.split(' ')[1];
    modal('Fijar clave del host SSH', h('div', null,
      h('p', null, 'Huella reportada por el servidor:'), h('pre', { class: 'code' }, scan.fingerprint),
      h('p', { class: 'muted' }, 'Verificá que coincide con la huella real del servidor (por otra vía) antes de confirmar. Los agentes solo se conectarán si el host presenta esta clave.'),
      same ? h('p', { class: 'tag ok' }, 'Ya estaba fijada con esta misma clave') : scan.current ? h('p', { class: 'error' }, 'Atención: la clave cambió respecto a la fijada actualmente.') : null), [
      { label: 'Cancelar', run: () => true },
      { label: 'Fijar esta clave', cls: 'primary', run: async () => { await api(`/credentials/${c.id}/pin-host-key`, { method: 'POST', body: { host_key: scan.host_key } }); toast('Clave fijada'); load(); } },
    ]);
  }
}

// ------------------------------------------------------------------ vistas: agentes

function mcpSnippets(token) {
  const url = `${location.origin}/mcp`;
  return h('div', null,
    h('p', null, h('strong', null, 'Copiá el token ahora: no se vuelve a mostrar.')),
    h('pre', { class: 'code' }, token), h('button', { class: 'btn small', onclick: () => copy(token) }, 'Copiar token'),
    h('p', { class: 'muted' }, 'Claude Code:'),
    h('pre', { class: 'code' }, `claude mcp add --transport http llaverito ${url} --header "Authorization: Bearer ${token}"`),
    h('p', { class: 'muted' }, 'Configuración JSON genérica:'),
    h('pre', { class: 'code' }, JSON.stringify({ mcpServers: { llaverito: { type: 'http', url, headers: { Authorization: `Bearer ${token}` } } } }, null, 2)));
}

function grantPicker(selected) {
  const boxes = state.folders.map((fo) => ({ fo, c: check(fo.name, selected.has(fo.id)) }));
  return { node: h('div', null, h('div', { class: 'muted small' }, 'Carpetas a las que tendrá acceso'), boxes.map((b) => b.c.node)),
    value: () => boxes.filter((b) => b.c.input.checked).map((b) => ({ folder_id: b.fo.id })) };
}

async function viewAgents(root) {
  state.folders = await api('/folders');
  const agents = await api('/agents');
  const names = Object.fromEntries(state.folders.map((f) => [f.id, f.name]));
  const create = () => {
    const name = h('input', { type: 'text', placeholder: 'ej. asistente-infra' });
    const days = h('input', { type: 'number', min: 1, placeholder: 'Sin vencimiento' });
    const picker = grantPicker(new Set());
    modal('Nuevo agente', h('div', null, field('Nombre', name), field('Vence en (días)', days), picker.node), [
      { label: 'Cancelar', run: () => true },
      { label: 'Crear', cls: 'primary', run: async () => {
        const r = await api('/agents', { method: 'POST', body: { name: name.value, expires_in_days: days.value ? Number(days.value) : null, grants: picker.value() } });
        modal('Token del agente', mcpSnippets(r.token), [{ label: 'Listo', run: () => true }]);
        setTimeout(() => navigate(), 0);
      } },
    ]);
  };
  const editGrants = (a) => {
    const picker = grantPicker(new Set(a.grants.map((g) => g.folder_id).filter(Boolean)));
    const extra = a.grants.filter((g) => g.credential_id).length;
    modal(`Permisos de ${a.name}`, h('div', null, picker.node, extra ? h('p', { class: 'hint' }, `Tiene ${extra} permiso(s) sobre credenciales individuales que se conservarán.`) : null), [
      { label: 'Cancelar', run: () => true },
      { label: 'Guardar', cls: 'primary', run: async () => {
        const keep = a.grants.filter((g) => g.credential_id).map((g) => ({ credential_id: g.credential_id }));
        await api(`/agents/${a.id}/grants`, { method: 'PUT', body: [...picker.value(), ...keep] }); toast('Permisos actualizados'); navigate();
      } },
    ]);
  };
  const revoke = async (a) => { if (confirm(`¿Revocar "${a.name}"? Su token dejará de funcionar.`)) { await api('/agents/' + a.id, { method: 'DELETE' }); navigate(); } };

  root.append(
    h('div', { class: 'row between' }, h('h1', null, 'Agentes'), state.user.role === 'viewer' ? null : h('button', { class: 'btn primary', onclick: create }, '+ Nuevo agente')),
    h('p', { class: 'muted' }, 'Un agente es un cliente MCP (Claude Code, Claude Desktop, etc.) con su propio token. Usa las credenciales sin ver nunca los secretos.'),
    h('div', { class: 'panel' }, agents.length ? h('table', null,
      h('thead', null, h('tr', null, ['Agente', 'Token', 'Acceso', 'Último uso', 'Estado', ''].map((x) => h('th', null, x)))),
      h('tbody', null, agents.map((a) => h('tr', null,
        h('td', null, h('strong', null, a.name)), h('td', { class: 'mono' }, a.token_prefix + '…'),
        h('td', null, a.grants.map((g) => h('span', { class: 'tag' }, g.folder_id ? (names[g.folder_id] || 'carpeta') : 'credencial'))),
        h('td', null, fmt(a.last_used_at)),
        h('td', null, a.revoked ? h('span', { class: 'tag denied' }, 'revocado') : a.expires_at ? `vence ${fmt(a.expires_at)}` : h('span', { class: 'tag ok' }, 'activo')),
        h('td', { class: 'row' }, a.revoked ? null : [h('button', { class: 'btn small', onclick: () => editGrants(a) }, 'Permisos'), h('button', { class: 'btn small danger', onclick: () => revoke(a) }, 'Revocar')])))))
      : h('div', { class: 'empty' }, 'Todavía no hay agentes.')));
}

// ------------------------------------------------------------------ vistas: aprobaciones

async function viewApprovals(root) {
  const box = h('div');
  const draw = async () => {
    const all = await api('/approvals');
    const pending = all.filter((a) => a.status === 'pending');
    state.pending = pending.length; drawBadge();
    const decide = async (a, approve) => { await api(`/approvals/${a.id}/decide`, { method: 'POST', body: { approve } }); toast(approve ? 'Aprobada' : 'Rechazada'); draw(); };
    box.replaceChildren(h('div', null,
      h('h2', null, `Pendientes (${pending.length})`),
      pending.length ? pending.map((a) => h('div', { class: 'card' },
        h('div', { class: 'row between' }, h('div', null, h('strong', null, a.agent), ' quiere usar ', h('code', null, a.credential)), h('span', { class: 'muted small' }, `vence ${fmt(a.expires_at)}`)),
        h('pre', { class: 'code' }, `${a.action}: ${a.summary}`), h('div', { class: 'muted small' }, `Motivo: ${a.reason}`),
        h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: () => decide(a, true) }, 'Aprobar (un solo uso)'), h('button', { class: 'btn danger', onclick: () => decide(a, false) }, 'Rechazar'))))
        : h('div', { class: 'empty' }, 'No hay solicitudes pendientes.'),
      h('h2', null, 'Historial'),
      h('div', { class: 'panel' }, h('table', null, h('tbody', null, all.filter((a) => a.status !== 'pending').slice(0, 30).map((a) => h('tr', null,
        h('td', null, fmt(a.requested_at)), h('td', null, a.agent), h('td', { class: 'mono' }, a.credential), h('td', { class: 'mono' }, a.summary), h('td', null, h('span', { class: `tag ${a.status === 'approved' || a.status === 'consumed' ? 'ok' : 'denied'}` }, a.status)))))))));
  };
  root.append(h('h1', null, 'Aprobaciones'), box);
  await draw();
  clearInterval(state.timer);
  state.timer = setInterval(() => { if (location.hash.startsWith('#/aprobaciones')) draw().catch(() => {}); }, 6000);
}

// ------------------------------------------------------------------ vistas: auditoría

async function viewAudit(root) {
  const action = h('input', { type: 'text', placeholder: 'Filtrar por acción (ej. http_request)' });
  const tbody = h('tbody');
  const more = h('button', { class: 'btn' }, 'Cargar más');
  let last = null;
  const load = async (reset) => {
    if (reset) { last = null; tbody.replaceChildren(); }
    const qs = new URLSearchParams({ limit: '100' });
    if (last) qs.set('before_id', last);
    if (action.value.trim()) qs.set('action', action.value.trim());
    const rows = await api('/audit?' + qs);
    if (rows.length) last = rows[rows.length - 1].id;
    more.classList.toggle('hidden', rows.length < 100);
    tbody.append(...rows.map((e) => h('tr', null, h('td', { class: 'mono' }, fmt(e.ts)), h('td', null, `${e.actor_type}: ${e.actor || '—'}`), h('td', null, e.action),
      h('td', null, h('span', { class: `tag ${e.outcome}` }, e.outcome)), h('td', { class: 'mono' }, e.credential || ''), h('td', { class: 'mono small' }, e.target || '', e.detail && Object.keys(e.detail).length ? ' ' + JSON.stringify(e.detail) : ''))));
  };
  const verify = async () => { const r = await api('/audit/verify'); toast(r.ok ? `Integridad verificada (${r.checked} registros)` : `¡Cadena rota en el registro ${r.broken_at}!`); };
  action.addEventListener('change', () => load(true));
  more.addEventListener('click', () => load(false));
  root.append(h('div', { class: 'row between' }, h('h1', null, 'Auditoría'), h('button', { class: 'btn', onclick: verify }, 'Verificar integridad')),
    h('div', { class: 'panel' }, h('div', { class: 'row' }, h('div', { class: 'grow' }, action)),
      h('table', null, h('thead', null, h('tr', null, ['Fecha', 'Actor', 'Acción', 'Resultado', 'Credencial', 'Detalle'].map((x) => h('th', null, x)))), tbody), h('div', { class: 'row' }, more)));
  await load(true);
}

// ------------------------------------------------------------------ vistas: usuarios y carpetas

async function viewUsers(root) {
  const [users, folders] = await Promise.all([api('/users'), api('/folders')]);
  const ROLES = { admin: 'Administrador', editor: 'Editor', viewer: 'Lector' };
  const roleSelect = (v) => h('select', null, Object.entries(ROLES).map(([k, l]) => h('option', { value: k, selected: k === v }, l)));

  const createUser = () => {
    const email = h('input', { type: 'email' }), name = h('input', { type: 'text' }), pw = h('input', { type: 'password', autocomplete: 'new-password' }), role = roleSelect('viewer');
    modal('Nuevo usuario', h('div', null, field('Email', email), field('Nombre', name), field('Contraseña inicial (mín. 12)', pw), field('Rol', role)), [
      { label: 'Cancelar', run: () => true },
      { label: 'Crear', cls: 'primary', run: async () => { await api('/users', { method: 'POST', body: { email: email.value, name: name.value, password: pw.value, role: role.value } }); navigate(); } },
    ]);
  };
  const editUser = (u) => {
    const role = roleSelect(u.role), active = check('Activo', u.active), pw = h('input', { type: 'password', autocomplete: 'new-password' });
    const isAd = u.auth_source === 'ad';
    modal(u.email, h('div', null, field('Rol', role), active.node,
      isAd ? h('p', { class: 'hint' }, `Cuenta de Active Directory${u.department ? ' · ' + u.department : ''}: la contraseña se gestiona en AD.`) : field('Nueva contraseña (opcional)', pw)), [
      { label: 'Cancelar', run: () => true },
      { label: 'Guardar', cls: 'primary', run: async () => {
        const body = { role: role.value, active: active.input.checked }; if (pw.value) body.password = pw.value;
        await api('/users/' + u.id, { method: 'PATCH', body }); navigate();
      } },
    ]);
  };
  const createFolder = () => {
    const name = h('input', { type: 'text' }), desc = h('input', { type: 'text' });
    modal('Nueva carpeta', h('div', null, field('Nombre', name), field('Descripción', desc)), [
      { label: 'Cancelar', run: () => true },
      { label: 'Crear', cls: 'primary', run: async () => { await api('/folders', { method: 'POST', body: { name: name.value, description: desc.value } }); navigate(); } },
    ]);
  };
  const access = async (fo) => {
    const current = Object.fromEntries((await api(`/folders/${fo.id}/access`)).map((a) => [a.user_id, a.level]));
    const sels = users.filter((u) => u.role !== 'admin').map((u) => ({ u, s: h('select', null, [['', 'Sin acceso'], ['read', 'Lectura'], ['write', 'Escritura']].map(([v, l]) => h('option', { value: v, selected: (current[u.id] || '') === v }, l))) }));
    modal(`Acceso a ${fo.name}`, h('div', null, h('p', { class: 'hint' }, 'Los administradores acceden a todo. Los lectores nunca escriben, aunque tengan "Escritura".'),
      sels.map(({ u, s }) => h('div', { class: 'row between card' }, h('span', null, `${u.name} · ${u.email}`), s))), [
      { label: 'Cancelar', run: () => true },
      { label: 'Guardar', cls: 'primary', run: async () => {
        await api(`/folders/${fo.id}/access`, { method: 'PUT', body: sels.filter(({ s }) => s.value).map(({ u, s }) => ({ user_id: u.id, level: s.value })) }); toast('Acceso actualizado');
      } },
    ]);
  };
  const delFolder = async (fo) => { if (confirm(`¿Eliminar la carpeta "${fo.name}"?`)) { try { await api('/folders/' + fo.id, { method: 'DELETE' }); navigate(); } catch (e) { toast(e.message); } } };

  root.append(
    h('div', { class: 'row between' }, h('h1', null, 'Usuarios y carpetas'), h('div', { class: 'row' }, h('button', { class: 'btn', onclick: createFolder }, '+ Carpeta'), h('button', { class: 'btn primary', onclick: createUser }, '+ Usuario'))),
    h('div', { class: 'panel' }, h('h2', null, 'Usuarios'), h('table', null, h('tbody', null, users.map((u) => h('tr', null,
      h('td', null, h('strong', null, u.name)), h('td', null, u.email), h('td', null, h('span', { class: 'tag' }, ROLES[u.role]), u.auth_source === 'ad' ? h('span', { class: 'tag' }, 'AD') : null), h('td', null, u.active ? '' : h('span', { class: 'tag denied' }, 'inactivo')),
      h('td', null, h('button', { class: 'btn small', onclick: () => editUser(u) }, 'Editar'))))))),
    h('p'),
    h('div', { class: 'panel' }, h('h2', null, 'Carpetas'), folders.length ? h('table', null, h('tbody', null, folders.map((fo) => h('tr', null,
      h('td', null, h('strong', null, fo.name)), h('td', { class: 'muted' }, fo.description),
      h('td', { class: 'row' }, h('button', { class: 'btn small', onclick: () => access(fo) }, 'Acceso'), h('button', { class: 'btn small danger', onclick: () => delFolder(fo) }, 'Eliminar')))))) : h('div', { class: 'empty' }, 'Todavía no hay carpetas.')));
}

// ------------------------------------------------------------------ shell, login y router

const ROUTES = [
  ['#/credenciales', 'Credenciales', viewCredentials],
  ['#/agentes', 'Agentes', viewAgents],
  ['#/aprobaciones', 'Aprobaciones', viewApprovals],
  ['#/auditoria', 'Auditoría', viewAudit, 'admin'],
  ['#/usuarios', 'Usuarios', viewUsers, 'admin'],
];

function drawBadge() {
  const el = document.getElementById('badge');
  if (!el) return;
  el.textContent = state.pending || '';
  el.classList.toggle('hidden', !state.pending);
}

async function refreshPending() {
  try { state.pending = (await api('/approvals?status=pending')).length; drawBadge(); } catch { /* sesión vencida: lo maneja api() */ }
}

function viewLogin() {
  const email = h('input', { type: 'email', autocomplete: 'username' }), pw = h('input', { type: 'password', autocomplete: 'current-password' });
  const err = h('div', { class: 'error' });
  const submit = async (e) => {
    e.preventDefault(); err.textContent = '';
    try { state.user = await api('/auth/login', { method: 'POST', body: { email: email.value, password: pw.value } }); render(); }
    catch (ex) { err.textContent = ex.message; }
  };
  const hint = h('p', { class: 'hint' });
  api('/auth/config').then((c) => {
    if (c.ad_enabled) hint.textContent = `Ingresá con tu correo institucional (@${c.ad_domain}) y tu contraseña de Windows.`;
  }).catch(() => {});
  return h('form', { class: 'login panel', onsubmit: submit }, h('h1', null, '🔑 Llaverito'), h('p', { class: 'muted' }, 'Bóveda de credenciales — Municipalidad de Vicente López'),
    field('Email', email), field('Contraseña', pw), hint, err, h('button', { class: 'btn primary', type: 'submit' }, 'Ingresar'));
}

async function navigate() {
  clearInterval(state.timer);
  const route = ROUTES.find((r) => location.hash.startsWith(r[0])) || ROUTES[0];
  const main = document.getElementById('main');
  main.replaceChildren();
  document.querySelectorAll('header nav a').forEach((a) => a.classList.toggle('active', a.getAttribute('href') === route[0]));
  try { await route[2](main); } catch (e) { main.append(h('div', { class: 'error' }, e.message)); }
}

async function render() {
  clearInterval(state.timer);
  $app.replaceChildren();
  if (!state.user) { $app.append(viewLogin()); return; }
  const nav = ROUTES.filter((r) => !r[3] || r[3] === state.user.role).map((r) => h('a', { href: r[0] }, r[1], r[0] === '#/aprobaciones' ? h('span', { class: 'badge hidden', id: 'badge' }) : null));
  const logout = async () => { await api('/auth/logout', { method: 'POST' }); state.user = null; render(); };
  $app.append(h('header', { class: 'top' }, h('div', { class: 'logo' }, '🔑 Llaverito'), h('nav', null, nav),
    h('div', { class: 'who' }, `${state.user.name} · ${state.user.role}`, h('button', { class: 'btn small', onclick: logout }, 'Salir'))), h('main', { id: 'main' }));
  refreshPending();
  await navigate();
}

window.addEventListener('hashchange', () => state.user && navigate());
setInterval(() => state.user && !location.hash.startsWith('#/aprobaciones') && refreshPending(), 20000);

(async () => {
  try { state.user = await api('/auth/me'); } catch { state.user = null; }
  render();
})();
