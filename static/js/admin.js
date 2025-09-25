/* global window, document, fetch */
(() => {
  const els = {
    status: document.getElementById('status'),
    usersTbody: document.getElementById('users-tbody'),
    btnCreate: document.getElementById('btn-create-user'),
    newUsername: document.getElementById('new-username'),
    newPassword: document.getElementById('new-password'),
    btnLogout: document.getElementById('btn-logout'),
    btnViewLogs: document.getElementById('btn-view-logs'),
  };

  function setStatus(t) { els.status.textContent = t || ''; }

  async function api(url, opts={}) {
    const res = await fetch(url, { headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' }, credentials: 'same-origin', ...opts });
    if (res.status === 401) { window.location.href = '/login'; throw new Error('Giriş gerekli'); }
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await res.json() : null;
    if (!res.ok || (data && data.ok === false)) { throw new Error((data && data.error) || res.statusText); }
    return data;
  }

  els.btnLogout?.addEventListener('click', async () => {
    try { await api('/logout', { method: 'POST' }); } catch (e) {}
    window.location.href = '/login';
  });

  async function loadUsers() {
    setStatus('Yükleniyor…');
    try {
      const data = await api('/api/admin/users');
      renderUsers(data.users || {}, data.levels || {});
    } catch (e) {
      setStatus(e.message || 'Hata');
    } finally {
      setStatus('');
    }
  }

  function renderUsers(users, levels) {
    els.usersTbody.innerHTML = '';
    const toLabel = (lvl) => {
      if (lvl === levels.FULL) return 'FULL';
      if (lvl === levels.WRITE) return 'WRITE';
      if (lvl === levels.READ) return 'READ';
      return 'NONE';
    };
    Object.keys(users).sort((a,b)=>a.localeCompare(b,'tr')).forEach((uname) => {
      const info = users[uname] || {};
      const perms = info.perms || {};
      const pairs = Object.keys(perms).sort((a,b)=>a.localeCompare(b,'tr')).map(k => `${k}: ${toLabel(perms[k])}`);
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="px-3 py-2 text-sm">${escapeHtml(uname)}</td>
        <td class="px-3 py-2 text-sm text-gray-700">${pairs.join(', ') || '-'}</td>
        <td class="px-3 py-2 text-right">
          <button class="rounded border px-2 py-1 text-sm hover:bg-gray-50" data-act="set-pass" data-user="${escapeAttr(uname)}">Şifre</button>
          <button class="rounded border px-2 py-1 text-sm hover:bg-gray-50" data-act="set-perms-ui" data-user="${escapeAttr(uname)}">Yetkiler</button>
          ${uname === 'admin' ? '' : '<button class="rounded border px-2 py-1 text-sm text-rose-600 border-rose-300 hover:bg-rose-50" data-act="del" data-user="'+escapeAttr(uname)+'">Sil</button>'}
        </td>`;
      els.usersTbody.appendChild(tr);
    });

    els.usersTbody.querySelectorAll('button[data-act]')?.forEach(btn => {
      btn.addEventListener('click', async () => {
        const uname = btn.getAttribute('data-user');
        const act = btn.getAttribute('data-act');
        try {
          if (act === 'del') {
            if (!confirm(`${uname} silinsin mi?`)) return;
            await api('/api/admin/delete-user', { method: 'POST', body: JSON.stringify({ username: uname }) });
          } else if (act === 'set-pass') {
            const pw = prompt('Yeni şifre:');
            if (!pw) return;
            await api('/api/admin/set-password', { method: 'POST', body: JSON.stringify({ username: uname, password: pw }) });
          } else if (act === 'set-perms-ui') {
            await openPermsDialog(uname);
          }
          await loadUsers();
        } catch (e) {
          alert(e.message || 'Hata');
        }
      });
    });
  }

  async function openPermsDialog(username) {
    try {
      const [usersRes, headsRes] = await Promise.all([
        api('/api/admin/users'),
        api('/api/admin/heads')
      ]);
      const allUsers = usersRes.users || {};
      const levels = usersRes.levels || {};
      const heads = headsRes.heads || [];
      const current = (allUsers[username]?.perms) || {};

      const container = document.createElement('div');
      container.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/30';
      container.innerHTML = `
        <div class="w-full max-w-lg rounded-lg bg-white shadow p-4">
          <div class="mb-3 font-semibold">${escapeHtml(username)} yetkileri</div>
          <div class="space-y-2 max-h-[60vh] overflow-auto" id="perms-list"></div>
          <div class="mt-4 flex justify-end gap-2">
            <button id="dlg-cancel" class="rounded border px-3 py-1.5 text-sm">İptal</button>
            <button id="dlg-save" class="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white">Kaydet</button>
          </div>
        </div>`;
      document.body.appendChild(container);

      const list = container.querySelector('#perms-list');
      const levelOptions = [
        { key: 'NONE', val: levels.NONE, label: 'Yok' },
        { key: 'READ', val: levels.READ, label: 'Okuma' },
        { key: 'WRITE', val: levels.WRITE, label: 'Yazma' },
        { key: 'FULL', val: levels.FULL, label: 'Tam' },
      ];

      heads.forEach(h => {
        const row = document.createElement('div');
        row.className = 'flex items-center justify-between gap-3 border rounded p-2';
        const selected = current[h] ?? levels.NONE;
        const chkNone = `<label class="inline-flex items-center gap-1 text-sm">
              <input type="checkbox" data-head="${h}" data-kind="NONE" value="${levels.NONE}" ${selected === levels.NONE ? 'checked' : ''} class="accent-indigo-600 perm-chk" /> Yok
            </label>`;
        const chkRead = `<label class="inline-flex items-center gap-1 text-sm">
              <input type="checkbox" data-head="${h}" data-kind="READ" value="${levels.READ}" ${(selected >= levels.READ) ? 'checked' : ''} class="accent-indigo-600 perm-chk" /> Okuma
            </label>`;
        const chkWrite = `<label class="inline-flex items-center gap-1 text-sm">
              <input type="checkbox" data-head="${h}" data-kind="WRITE" value="${levels.WRITE}" ${(selected >= levels.WRITE) ? 'checked' : ''} class="accent-indigo-600 perm-chk" /> Yazma
            </label>`;
        const chkFull = `<label class="inline-flex items-center gap-1 text-sm">
              <input type="checkbox" data-head="${h}" data-kind="FULL" value="${levels.FULL}" ${(selected >= levels.FULL) ? 'checked' : ''} class="accent-indigo-600 perm-chk" /> Tam
            </label>`;
        row.innerHTML = `
          <div class="font-medium">${escapeHtml(h)}</div>
          <div class="flex items-center gap-3">${chkNone} ${chkRead} ${chkWrite} ${chkFull}</div>`;
        list.appendChild(row);
      });

      container.querySelector('#dlg-cancel').addEventListener('click', () => container.remove());
      container.querySelector('#dlg-save').addEventListener('click', async () => {
        const all = list.querySelectorAll('.perm-chk');
        const perHead = new Map();
        all.forEach(inp => {
          const h = inp.getAttribute('data-head');
          const kind = inp.getAttribute('data-kind');
          const val = Number(inp.value);
          if (!perHead.has(h)) perHead.set(h, { none: false, max: 0 });
          if (inp.checked) {
            const acc = perHead.get(h);
            if (kind === 'NONE') { acc.none = true; acc.max = 0; }
            else if (!acc.none) { acc.max = Math.max(acc.max, val); }
          }
        });
        const perms = {};
        perHead.forEach((acc, h) => { if (!acc.none && acc.max > 0) perms[h] = acc.max; });
        try {
          await api('/api/admin/set-perms', { method: 'POST', body: JSON.stringify({ username, perms }) });
          container.remove();
        } catch (e) {
          alert(e.message || 'Hata');
        }
      });

      // NONE seçilince diğerlerini kaldır, diğerleri seçilince NONE kaldır
      list.querySelectorAll('.perm-chk').forEach(inp => {
        inp.addEventListener('change', () => {
          const head = inp.getAttribute('data-head');
          const kind = inp.getAttribute('data-kind');
          const group = list.querySelectorAll(`.perm-chk[data-head="${head}"]`);
          if (kind === 'NONE' && inp.checked) {
            group.forEach(el => { if (el !== inp) el.checked = false; });
          } else if (kind !== 'NONE' && inp.checked) {
            group.forEach(el => { if (el.getAttribute('data-kind') === 'NONE') el.checked = false; });
          }
        });
      });
    } catch (e) {
      alert(e.message || 'Hata');
    }
  }

  els.btnCreate?.addEventListener('click', async () => {
    const u = (els.newUsername.value || '').trim();
    const p = (els.newPassword.value || '').trim();
    if (!u || !p) { alert('Kullanıcı ve şifre gerekli'); return; }
    try {
      await api('/api/admin/create-user', { method: 'POST', body: JSON.stringify({ username: u, password: p, perms: {} }) });
      els.newUsername.value = '';
      els.newPassword.value = '';
      await loadUsers();
    } catch (e) {
      alert(e.message || 'Hata');
    }
  });

  // Logs viewer modal
  els.btnViewLogs?.addEventListener('click', async () => {
    let page = 1; const size = 100;
    const container = document.createElement('div');
    container.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/30';
    container.innerHTML = `
      <div class="w-[min(95vw,80rem)] max-h-[85vh] overflow-hidden rounded-lg bg-white shadow flex flex-col">
        <div class="px-4 pt-4 pb-2 flex items-center justify-between border-b">
          <div class="font-semibold text-lg">📊 Sistem Aktivite Logları</div>
          <button id="logs-close" class="rounded border px-3 py-1.5 text-sm hover:bg-gray-100">✕ Kapat</button>
        </div>
        <div class="px-4 py-3 flex items-center justify-between gap-3 bg-gray-50 border-b">
          <div class="flex items-center gap-2">
            <button id="prev" class="rounded border px-3 py-1.5 text-sm bg-white hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed">← Önceki</button>
            <button id="next" class="rounded border px-3 py-1.5 text-sm bg-white hover:bg-gray-100">Sonraki →</button>
            <div id="meta" class="ml-3 text-sm text-slate-600 font-medium"></div>
          </div>
          <div class="text-xs text-slate-500">En son aktiviteler üstte gösterilir</div>
        </div>
        <div class="flex-1 overflow-auto">
          <table class="min-w-full table-auto">
            <thead class="bg-gray-100 sticky top-0">
              <tr>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-700 w-36">Tarih & Saat</th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-700 w-24">Kullanıcı</th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-700 w-28">Kategori</th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-700">İşlem Detayı</th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-700 w-20">IP</th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-700 w-20">Durum</th>
              </tr>
            </thead>
            <tbody id="logs-tbody"></tbody>
          </table>
        </div>
      </div>`;
    document.body.appendChild(container);
    const tbody = container.querySelector('#logs-tbody');
    const meta = container.querySelector('#meta');
    
    async function load() {
      try {
        const data = await api(`/api/admin/logs?page=${page}&size=${size}`);
        const entries = data.entries || [];
        tbody.innerHTML = entries.map(e => {
          // Use enhanced display fields
          const displayTime = e.time_only || e.time_tr || e.ts || '';
          const displayDate = e.date_tr || '';
          const description = e.description || e.action || '';
          const user = e.user_display || e.user || 'Anonim';
          const category = e.category || 'Diğer';
          const ip = e.ip || '-';
          const status = e.status || '';
          const statusText = e.status_text || '';
          
          // Color code status
          let statusClass = 'text-gray-600';
          let statusBg = 'bg-gray-100';
          if (status >= 200 && status < 300) {
            statusClass = 'text-green-700';
            statusBg = 'bg-green-100';
          } else if (status >= 400 && status < 500) {
            statusClass = 'text-amber-700';
            statusBg = 'bg-amber-100';
          } else if (status >= 500) {
            statusClass = 'text-red-700';
            statusBg = 'bg-red-100';
          }
          
          // Color code categories
          let categoryClass = 'bg-gray-100 text-gray-700';
          if (category === 'Güvenlik') categoryClass = 'bg-blue-100 text-blue-700';
          else if (category === 'Dosya İşlemleri') categoryClass = 'bg-green-100 text-green-700';
          else if (category === 'Sistem Erişimi') categoryClass = 'bg-purple-100 text-purple-700';
          
          return `<tr class="border-b hover:bg-blue-50 transition-colors">
            <td class="px-4 py-3">
              <div class="text-sm font-medium text-slate-900">${escapeHtml(displayTime)}</div>
              <div class="text-xs text-slate-600">${escapeHtml(displayDate)}</div>
            </td>
            <td class="px-4 py-3">
              <div class="text-sm font-medium text-slate-900">${escapeHtml(user)}</div>
            </td>
            <td class="px-4 py-3">
              <span class="inline-flex px-2 py-1 text-xs font-medium rounded-full ${categoryClass}">
                ${escapeHtml(category)}
              </span>
            </td>
            <td class="px-4 py-3">
              <div class="text-sm text-slate-900 leading-relaxed">${escapeHtml(description)}</div>
            </td>
            <td class="px-4 py-3">
              <code class="text-xs text-slate-600 bg-slate-100 px-1 py-0.5 rounded">${escapeHtml(ip)}</code>
            </td>
            <td class="px-4 py-3">
              ${status ? `<span class="inline-flex px-2 py-1 text-xs font-medium rounded-full ${statusClass} ${statusBg}">${escapeHtml(statusText)}</span>` : '-'}
            </td>
          </tr>`;
        }).join('');
        meta.innerHTML = `📈 <strong>Sayfa ${page}</strong> • Toplam <strong>${data.total}</strong> kayıt`;
        container.querySelector('#prev').disabled = page <= 1;
      } catch (e) {
        alert(e.message || 'Log yüklenemedi');
      }
    }
    container.querySelector('#prev').addEventListener('click', () => { if (page > 1) { page--; load(); } });
    container.querySelector('#next').addEventListener('click', () => { page++; load(); });
    container.querySelector('#logs-close').addEventListener('click', () => container.remove());
    load();
  });

  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c])); }
  function escapeAttr(s) { return String(s).replace(/"/g, '&quot;'); }

  loadUsers();
})();


