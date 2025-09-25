/* global window, document, history, location, fetch */
(() => {
  const els = {
    foldersGrid: document.getElementById('folders-grid'),
    foldersEmpty: document.getElementById('folders-empty'),
    filesTbody: document.getElementById('files-tbody'),
    filesEmpty: document.getElementById('files-empty'),
    filesSection: document.getElementById('files-section'),
    filesThead: document.getElementById('files-thead'),
    currentFolder: document.getElementById('current-folder'),
    breadcrumb: document.getElementById('breadcrumb'),
    status: document.getElementById('status'),
    btnNewFolder: document.getElementById('btn-new-folder'),
    btnUploadFiles: document.getElementById('btn-upload-files'),
    btnUploadFolder: document.getElementById('btn-upload-folder'),
    filePicker: document.getElementById('file-picker'),
    folderPicker: document.getElementById('folder-picker'),
    dropOverlay: document.getElementById('drop-overlay'),
    toast: document.getElementById('toast'),
    toastInner: document.getElementById('toast-inner'),
    uploadProgress: document.getElementById('upload-progress'),
    uploadProgressText: document.getElementById('upload-progress-text'),
    uploadProgressBar: document.getElementById('upload-progress-bar'),
    conflictModal: document.getElementById('conflict-modal'),
    conflictClose: document.getElementById('conflict-close'),
    conflictOverwrite: document.getElementById('conflict-overwrite'),
    conflictRename: document.getElementById('conflict-rename'),
    conflictSkip: document.getElementById('conflict-skip'),
    conflictCurrent: document.getElementById('conflict-current'),
    conflictNewname: document.getElementById('conflict-newname'),
    userChip: document.getElementById('user-chip'),
    btnLogout: document.getElementById('btn-logout'),
    btnAdmin: document.getElementById('btn-admin'),
    searchInput: document.getElementById('search-input'),
    viewGrid: document.getElementById('view-grid'),
    viewList: document.getElementById('view-list'),
    // file view buttons removed
    folderSort: document.getElementById('folder-sort'),
    fileSort: document.getElementById('file-sort'),
    folderOpModal: document.getElementById('folder-op-modal'),
    folderOpClose: document.getElementById('folder-op-close'),
    folderOpSource: document.getElementById('folder-op-source'),
    folderOpDestInput: document.getElementById('folder-op-dest-input'),
    folderOpDatalist: document.getElementById('folder-op-datalist'),
    folderOpDestWrap: document.getElementById('folder-op-dest-wrap'),
    folderOpNewname: document.getElementById('folder-op-newname'),
    folderOpCancel: document.getElementById('folder-op-cancel'),
    folderOpConfirm: document.getElementById('folder-op-confirm'),
  };

  let allFolders = [];
  let currentFolder = getFolderFromPath();
  let folderViewMode = 'grid'; // 'grid' | 'list'
  // file view modes removed; always render table-like list
  let latestSearchToken = 0;

  function getFolderFromPath() {
    const raw = location.pathname.replace(/^\/+|\/+$/g, '');
    return decodeURIComponent(raw || '');
  }
  function encodeFolderPath(path) {
    // Clean and normalize path first
    const cleanPath = (path || '').replace(/\\/g, '/').replace(/\/+/g, '/');
    return cleanPath.split('/').map(encodeURIComponent).join('/');
  }
  function setStatus(text) { els.status.textContent = text || ''; }
  function isRoot() { return !currentFolder; }

  function showToast(msg, type = 'info') {
    const colors = {
      info: 'bg-slate-800 text-white',
      success: 'bg-emerald-600 text-white',
      error: 'bg-rose-600 text-white',
      warn: 'bg-amber-500 text-white',
    };
    els.toastInner.className = `rounded-md px-4 py-2 shadow-lg ${colors[type] || colors.info}`;
    els.toastInner.textContent = msg;
    els.toast.classList.remove('hidden');
    setTimeout(() => els.toast.classList.add('hidden'), 2500);
  }

  // Upload progress UI
  function showProgress(percent, text) {
    if (!els.uploadProgress) return;
    els.uploadProgress.classList.remove('hidden');
    if (els.uploadProgressText) els.uploadProgressText.textContent = text || `Yükleniyor… %${Math.floor(percent)}`;
    if (els.uploadProgressBar) els.uploadProgressBar.style.width = Math.max(0, Math.min(100, percent)) + '%';
  }
  function hideProgress() {
    els.uploadProgress?.classList.add('hidden');
  }

  // Conflict modal per item (returns {action, newName})
  function resolveConflictModal(originalName) {
    return new Promise((resolve) => {
      const m = els.conflictModal; if (!m) return resolve({ action: 'rename', newName: originalName });
      els.conflictCurrent && (els.conflictCurrent.textContent = originalName);
      if (els.conflictNewname) { els.conflictNewname.value = originalName; els.conflictNewname.focus(); }
      m.classList.remove('hidden'); m.classList.add('flex');
      const done = (res) => { m.classList.add('hidden'); m.classList.remove('flex'); resolve(res); };
      const onClose = () => done({ action: 'rename', newName: originalName });
      const onOverwrite = () => done({ action: 'overwrite' });
      const onRename = () => done({ action: 'rename', newName: (els.conflictNewname?.value || originalName).trim() || originalName });
      const onSkip = () => done({ action: 'cancel' });
      els.conflictClose?.addEventListener('click', onClose, { once: true });
      els.conflictOverwrite?.addEventListener('click', onOverwrite, { once: true });
      els.conflictRename?.addEventListener('click', onRename, { once: true });
      els.conflictSkip?.addEventListener('click', onSkip, { once: true });
    });
  }

  // API helper: 401 => /login; handle JSON responses
  async function api(url, opts = {}) {
    // ensure cookies (session) are sent with requests
    const res = await fetch(url, { headers: { 'Accept': 'application/json' }, credentials: 'same-origin', ...opts });
    if (res.status === 401) {
      // Oturum süresi dolmuş veya geçersiz - login sayfasına yönlendir
      window.location.href = '/login';
      return Promise.reject(new Error('Giriş gerekli'));
    }
    let data = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json();
    }
    if (!res.ok || (data && data.ok === false)) {
      const err = (data && data.error) || res.statusText || 'Hata';
      throw new Error(err);
    }
    return data;
  }

  // Load folders with user info
  async function loadFolders() {
    const data = await api('/api/folders');
    allFolders = data.folders || [];
    
    // Show user info with actual username
    const username = data.user || 'Kullanıcı';
    els.userChip.classList.remove('hidden');
    els.userChip.textContent = username;
    els.btnLogout.classList.remove('hidden');
    if (data.isAdmin && els.btnAdmin) { els.btnAdmin.classList.remove('hidden'); }
  }

  // --- Search helpers ---
  async function search(query, baseFolder) {
    const token = ++latestSearchToken;
    const params = new URLSearchParams();
    params.set('q', query);
    params.set('folder', baseFolder || '');
    const res = await api('/api/search?' + params.toString());
    if (token !== latestSearchToken) return null;
    return res;
  }

  function debounce(fn, wait) {
    let t = null;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), wait);
    };
  }

  // logout
  els.btnLogout.addEventListener('click', async () => {
    try {
      await api('/logout', { method: 'POST' });
    } catch (e) {
      // Logout hatası olsa bile login sayfasına git
      console.error('Logout error:', e);
    } finally {
      window.location.href = '/login';
    }
  });

  function getRootFolders() {
    let arr = Array.from(new Set(
      allFolders
        .filter(f => f && f.split('/').length === 1)
        .map(f => f.split('/')[0])
    ));
    const mode = els.folderSort?.value || 'name_asc';
    if (mode === 'name_desc') arr.sort((a,b)=>b.localeCompare(a,'tr'));
    else arr.sort((a,b)=>a.localeCompare(b,'tr'));
    return arr;
  }
  function getImmediateSubfolders(folder) {
    const set = new Set();
    const prefix = folder ? folder.replace(/\/+$/, '') + '/' : '';
    for (const f of allFolders) {
      if (!f || !prefix) continue;
      if (f.startsWith(prefix)) {
        const rest = f.slice(prefix.length);
        const first = rest.split('/')[0];
        if (first && first !== '.' && first !== '..') set.add(first);
      }
    }
    let arr = Array.from(set);
    const mode = els.folderSort?.value || 'name_asc';
    if (mode === 'name_desc') arr.sort((a,b)=>b.localeCompare(a,'tr'));
    else arr.sort((a,b)=>a.localeCompare(b,'tr'));
    return arr;
  }

  async function loadFiles(folder) {
    const data = folder
      ? await api('/api/' + encodeFolderPath(folder) + '/files')
      : await api('/api/files');
    let files = data.files || [];
    const mode = els.fileSort?.value || 'name_asc';
    files = [...files];
    const byName = (a,b)=>a.name.localeCompare(b.name,'tr');
    const bySize = (a,b)=>(a.size||0)-(b.size||0);
    const byDate = (a,b)=>new Date(a.modified).getTime()-new Date(b.modified).getTime();
    if (mode === 'name_asc') files.sort(byName);
    else if (mode === 'name_desc') files.sort((a,b)=>byName(b,a));
    else if (mode === 'size_asc') files.sort(bySize);
    else if (mode === 'size_desc') files.sort((a,b)=>bySize(b,a));
    else if (mode === 'date_asc') files.sort(byDate);
    else if (mode === 'date_desc') files.sort((a,b)=>byDate(b,a));
    return files;
  }

  // --- UI renderers ---
  function renderBreadcrumb() {
    const segments = currentFolder ? currentFolder.split('/') : [];
    const parts = [];
    parts.push(`<a href="/" data-nav="/" class="inline-flex items-center gap-1 rounded-full bg-slate-100 px-3 py-1 text-slate-700 hover:bg-slate-200 transition">🏠 Anasayfa</a>`);
    let pathAcc = '';
    segments.forEach((seg) => {
      pathAcc = pathAcc ? `${pathAcc}/${seg}` : seg;
      parts.push(`<span class="mx-1 text-gray-300">›</span>`);
      parts.push(`<a href="/${encodeFolderPath(pathAcc)}" data-nav="/${encodeFolderPath(pathAcc)}" class="inline-flex items-center gap-1 rounded-full bg-slate-100 px-3 py-1 text-slate-700 hover:bg-slate-200 transition">${escapeHtml(seg)}</a>`);
    });
    els.breadcrumb.innerHTML = parts.join('');
    els.currentFolder.textContent = currentFolder || '/';
    els.breadcrumb.querySelectorAll('a[data-nav]').forEach(a => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        navigateTo(a.getAttribute('data-nav').replace(/^\//, ''));
      });
    });
  }

  function renderFolders() {
    let items = isRoot() ? getRootFolders() : getImmediateSubfolders(currentFolder);
    // Switch grid/list layout classes on the container
    if (folderViewMode === 'grid') {
      els.foldersGrid.className = 'grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4';
    } else {
      els.foldersGrid.className = 'divide-y rounded-lg border bg-white';
    }
    els.foldersGrid.innerHTML = '';
    if (items.length === 0) {
      els.foldersEmpty.classList.remove('hidden');
      return;
    }
    els.foldersEmpty.classList.add('hidden');

    for (const name of items) {
      const card = document.createElement('div');
      const rootClasses = folderViewMode === 'grid'
        ? 'rounded-2xl bg-white/80 ring-1 ring-slate-200 hover:ring-indigo-200 hover:shadow-md'
        : 'border-b last:border-b-0';
      const subClasses = folderViewMode === 'grid'
        ? 'rounded-xl border border-slate-200 bg-white/90 hover:shadow-md hover:border-slate-300'
        : 'border-b last:border-b-0';
      const padding = folderViewMode === 'grid' ? 'p-4' : 'p-3';
      const layout = 'cursor-pointer flex items-center gap-3 transition';
      card.className = `group ${isRoot() ? rootClasses : subClasses} ${padding} ${layout}`;
      card.innerHTML = `
        <div class="flex h-10 w-10 items-center justify-center rounded-md bg-indigo-50 text-indigo-600">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="currentColor" viewBox="0 0 24 24"><path d="M10.414 5H20a2 2 0 0 1 2 2v1H2V7a2 2 0 0 1 2-2h5.586l.707.707L10.414 5z"/><path d="M2 9h20v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9z"/></svg>
        </div>
        <div class="flex-1 min-w-0">
          <div class="font-semibold truncate text-slate-800">${escapeHtml(name)}</div>
          <div class="text-xs text-gray-500">Klasör</div>
        </div>
        <div class="opacity-0 group-hover:opacity-100 transition text-gray-400">
          <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path d="M7 7h6v6H7V7z"/></svg>
        </div>
      `;
      card.addEventListener('click', () => {
        const next = currentFolder ? `${currentFolder}/${name}` : name;
        navigateTo(next);
      });
      // sağ tıkla klasör adı değiştirme (yetkin yoksa backend 403 döndürür)
      if (!isRoot()) {
        card.addEventListener('contextmenu', (e) => {
          e.preventDefault();
          openFolderOpModal(name);
        });
      }
      els.foldersGrid.appendChild(card);
    }
  }

  function renderFiles(files) {
    els.filesTbody.innerHTML = '';
    if (isRoot()) { 
      els.filesSection.classList.add('hidden'); 
      return; 
    }
    els.filesSection.classList.remove('hidden');

    if (!files || files.length === 0) {
      els.filesEmpty.classList.remove('hidden');
      return;
    }
    els.filesEmpty.classList.add('hidden');
    // Always show table header
    if (els.filesThead) {
      els.filesThead.classList.remove('hidden');
    }

    {
      for (const f of files) {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-50 transition-colors';
        tr.innerHTML = `
          <td class="px-4 py-2">
            <div class="flex items-center gap-2">
              <svg class="h-5 w-5 text-gray-400 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                <path d="M4 2h6l4 4v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z"/>
              </svg>
              <a href="${f.url}" target="_blank" class="text-indigo-600 hover:underline truncate">${escapeHtml(f.name)}</a>
            </div>
          </td>
          <td class="px-4 py-2 text-sm text-gray-600 whitespace-nowrap">${formatBytes(f.size || 0)}</td>
          <td class="px-4 py-2 text-sm text-gray-600 whitespace-nowrap">${formatDate(f.modified)}</td>
          <td class="px-4 py-2">
            <div class="flex justify-end gap-1 flex-wrap">
              <a class="inline-flex items-center gap-1 rounded-lg bg-blue-50 px-3 py-1.5 text-xs font-medium text-blue-700 hover:bg-blue-100 transition-colors" href="${f.url}?download=1">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-4-4m4 4l4-4m-6 2V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                </svg>
                İndir
              </a>
              <button class="inline-flex items-center gap-1 rounded-lg bg-gray-50 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-100 transition-colors btn-copy-path" data-path="${escapeAttr(f.path)}" data-url="${escapeAttr(f.url)}">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                </svg>
                Kopyala
              </button>
              <button class="inline-flex items-center gap-1 rounded-lg bg-orange-50 px-3 py-1.5 text-xs font-medium text-orange-700 hover:bg-orange-100 transition-colors btn-rename" data-path="${escapeAttr(f.path)}">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                </svg>
                Düzenle
              </button>
              <button class="inline-flex items-center gap-1 rounded-lg bg-red-50 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-100 transition-colors btn-delete" data-path="${escapeAttr(f.path)}">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                </svg>
                Sil
              </button>
            </div>
          </td>
        `;
        els.filesTbody.appendChild(tr);
      }
    }

    // Add event listeners after all rows are added
    els.filesTbody.querySelectorAll('.btn-rename').forEach(btn => {
      btn.addEventListener('click', async () => {
        const path = btn.getAttribute('data-path');
        const newName = prompt('Yeni ad:', path.split('/').pop());
        if (!newName) return;
        renameItem(path, newName);
      });
    });
    els.filesTbody.querySelectorAll('.btn-copy-path').forEach(btn => {
      btn.addEventListener('click', async () => {
        const path = btn.getAttribute('data-path');
        const url = btn.getAttribute('data-url');
        const base = location.origin;
        const absoluteUrl = base + url;
        const text = `${path}\n${absoluteUrl}`;
        try {
          await navigator.clipboard.writeText(text);
          showToast('Yol kopyalandı', 'success');
        } catch (e) {
          try {
            const ta = document.createElement('textarea');
            ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
            showToast('Yol kopyalandı', 'success');
          } catch (err) {
            showToast('Kopyalama başarısız', 'error');
          }
        }
      });
    });
    els.filesTbody.querySelectorAll('.btn-delete').forEach(btn => {
      btn.addEventListener('click', async () => {
        const path = btn.getAttribute('data-path');
        if (!confirm(`Silinsin mi?\n${path}`)) return;
        try {
          await api('/api/delete/' + encodeFolderPath(path), { method: 'POST' });
          showToast('Silindi', 'success');
          await refresh();
        } catch (e) {
          showToast(e.message || 'Hata', 'error');
        }
      });
    });
  }

  async function renameItem(path, newName) {
    try {
      await api('/api/rename/' + encodeFolderPath(path), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ newName })
      });
      showToast('Yeniden adlandırıldı', 'success');
      await refresh();
    } catch (e) {
      showToast(e.message || 'Hata', 'error');
    }
  }

  function navigateTo(folderPath) {
    const cleaned = (folderPath || '').replace(/^\/+|\/+$/g, '').replace(/\\/g, '/');
    const decoded = decodeURIComponent(cleaned);
    const newUrl = '/' + encodeFolderPath(decoded);
    try { sessionStorage.setItem('hisar_nav', '1'); } catch (e) {}
    
    // Use pushState for better navigation, fallback to location.href
    try {
      history.pushState(null, '', newUrl);
      currentFolder = getFolderFromPath();
      refresh();
    } catch (e) {
      location.href = newUrl; // fallback for older browsers
    }
  }

  async function refresh() {
    try {
      setStatus('Yükleniyor…');
      await loadFolders();
      renderBreadcrumb();
      renderFolders();
      const files = await loadFiles(currentFolder);
      renderFiles(files);
      setStatus('');
    } catch (e) {
      setStatus('');
      // Eğer authentication hatası ise, zaten api() fonksiyonu login sayfasına yönlendirdi
      if (String(e.message || '').includes('Giriş')) return;
      showToast(e.message || 'Hata', 'error');
      console.error(e);
    }
  }

  // --- Klasör oluşturma & yükleme ---
  els.btnNewFolder.addEventListener('click', async () => {
    if (isRoot()) { showToast('Anasayfada klasör oluşturma kapalı', 'warn'); return; }
    const name = prompt('Yeni klasör adı:');
    if (!name) return;
    try {
      // check conflict
      const exists = await api(`/api/exists?folder=${encodeURIComponent(currentFolder)}&name=${encodeURIComponent(name)}&type=dir`);
      if (exists?.exists) { showToast('Aynı isimde klasör var', 'error'); return; }
      const url = '/api/' + encodeFolderPath(currentFolder) + '/folders/' + encodeFolderPath(name);
      await api(url, { method: 'POST' });
      showToast('Klasör oluşturuldu', 'success');
      await refresh();
    } catch (e) {
      showToast(e.message || 'Hata', 'error');
    }
  });

  els.btnUploadFiles.addEventListener('click', () => {
    if (isRoot()) { showToast('Anasayfada yükleme kapalı', 'warn'); return; }
    els.filePicker.click();
  });
  els.filePicker.addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;
    await uploadBatch(files, files.map(f => f.name));
    e.target.value = '';
  });

  els.btnUploadFolder.addEventListener('click', () => {
    if (isRoot()) { showToast('Anasayfada yükleme kapalı', 'warn'); return; }
    els.folderPicker.click();
  });
  els.folderPicker.addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;
    const relPaths = files.map(f => f.webkitRelativePath || f.name);
    await uploadBatch(files, relPaths);
    e.target.value = '';
  });

  // Drag & drop
  let dragCounter = 0;
  window.addEventListener('dragenter', (e) => { e.preventDefault(); dragCounter++; els.dropOverlay.classList.remove('hidden'); });
  window.addEventListener('dragleave', (e) => { e.preventDefault(); dragCounter--; if (dragCounter <= 0) { dragCounter = 0; els.dropOverlay.classList.add('hidden'); }});
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', async (e) => {
    e.preventDefault(); dragCounter = 0; els.dropOverlay.classList.add('hidden');
    if (isRoot()) { showToast('Anasayfada yükleme kapalı', 'warn'); return; }

    const items = e.dataTransfer?.items ? Array.from(e.dataTransfer.items) : [];
    const filesOut = []; const relPathsOut = [];

    if (items.length && items[0].webkitGetAsEntry) {
      await Promise.all(items.map(item => {
        const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
        if (!entry) return;
        return traverseEntry(entry, '');
      }));
      async function traverseEntry(entry, path) {
        return new Promise((resolve) => {
          if (entry.isFile) {
            entry.file((file) => {
              const rp = path ? `${path}/${file.name}` : file.name;
              filesOut.push(file); relPathsOut.push(rp); resolve();
            }, () => resolve());
          } else if (entry.isDirectory) {
            const reader = entry.createReader();
            reader.readEntries(async (ents) => {
              for (const ent of ents) {
                await traverseEntry(ent, path ? `${path}/${entry.name}` : entry.name);
              }
              resolve();
            }, () => resolve());
          } else { resolve(); }
        });
      }
    } else {
      const files = Array.from(e.dataTransfer?.files || []);
      for (const f of files) { filesOut.push(f); relPathsOut.push(f.name); }
    }

    if (!filesOut.length) return;
    await uploadBatch(filesOut, relPathsOut);
  });

  async function uploadBatch(files, relPaths) {
    try {
      setStatus('Yükleniyor…');
      showProgress(0, 'Hazırlanıyor…');
      const CHUNK_SIZE = 10 * 1024 * 1024; // 10MB
      let uploadedCount = 0;
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        let rel = relPaths[i] || file.name;
        // Check existence before sending
        const existsCheck = await api(`/api/exists?folder=${encodeURIComponent(currentFolder || '')}&name=${encodeURIComponent(rel.split('/').pop())}&type=file`);
        let conflict = 'rename'; let newName = rel.split('/').pop();
        if (existsCheck?.exists) {
          const res = await resolveConflictModal(newName);
          if (res.action === 'cancel') {
            // skip this file
            continue;
          } else if (res.action === 'overwrite') {
            conflict = 'overwrite';
          } else if (res.action === 'rename') {
            conflict = 'rename';
            // replace only the leaf name in rel
            const parts = rel.split('/'); parts[parts.length - 1] = res.newName; rel = parts.join('/');
          }
        }
        const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
        const uploadId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
        for (let idx = 0; idx < totalChunks; idx++) {
          const start = idx * CHUNK_SIZE;
          const end = Math.min(file.size, start + CHUNK_SIZE);
          const blob = file.slice(start, end);
          const fd = new FormData();
          fd.append('chunk', blob);
          fd.append('folder', currentFolder || '');
          fd.append('relativePath', rel);
          fd.append('uploadId', uploadId);
          fd.append('chunkIndex', String(idx));
          fd.append('totalChunks', String(totalChunks));
          fd.append('conflict', conflict);

          await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/upload-chunk');
            xhr.responseType = 'json';
            xhr.setRequestHeader('Accept', 'application/json');
            xhr.upload.onprogress = (e) => {
              if (e.lengthComputable) {
                // overall percent across all files/chunks
                const chunkProgress = e.loaded / (end - start);
                const fileProgress = ((idx + chunkProgress) / totalChunks) * 100;
                const overall = ((i + fileProgress / 100) / files.length) * 100;
                const label = `Yükleniyor (${i+1}/${files.length})… %${Math.floor(overall)}`;
                showProgress(overall, label);
              }
            };
            xhr.onload = () => {
              const ok = xhr.status >= 200 && xhr.status < 300;
              const data = xhr.response || {};
              if (!ok || data.ok === false) reject(new Error((data && data.error) || xhr.statusText));
              else resolve(data);
            };
            xhr.onerror = () => reject(new Error('Yükleme hatası'));
            xhr.send(fd);
          });
        }
        uploadedCount++;
        // Büyük seçimlerde UI'yi dondurmamak için ara ver
        if ((i + 1) % 50 === 0) {
          await new Promise(requestAnimationFrame);
        }
      }
      showToast('Yükleme tamamlandı', 'success');
      await refresh();
    } catch (e) {
      showToast(e.message || 'Yükleme hatası', 'error');
    } finally {
      setStatus('');
      hideProgress();
    }
  }

  // Utils
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({'&': '&amp;','<': '&lt;','>': '&gt;','"': '&quot;',"'": '&#39;'}[c])); }
  function escapeAttr(s) { return String(s).replace(/"/g, '&quot;'); }
  function formatDate(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
  }
  function formatBytes(bytes) {
    const thresh = 1024; if (Math.abs(bytes) < thresh) return bytes + ' B';
    const units = ['KB','MB','GB','TB','PB','EB','ZB','YB']; let u = -1;
    do { bytes /= thresh; ++u; } while (Math.abs(bytes) >= thresh && u < units.length - 1);
    return bytes.toFixed(1) + ' ' + units[u];
  }

  // History navigation
  window.addEventListener('popstate', () => { currentFolder = getFolderFromPath(); refresh(); });

  // Debounced search listener
  if (els.searchInput) {
    const onSearchInput = debounce(async () => {
      const q = (els.searchInput?.value || '').trim();
      if (!q) { await refresh(); return; }
      try {
        setStatus('Aranıyor…');
        const data = await search(q, currentFolder);
        if (!data) return;
        // Render matching folders
        els.foldersGrid.innerHTML = '';
        if (!data.folders || data.folders.length === 0) {
          els.foldersEmpty.classList.remove('hidden');
        } else {
          els.foldersEmpty.classList.add('hidden');
          for (const f of data.folders) {
            const name = f.split('/').slice(-1)[0];
            const card = document.createElement('div');
            const classes = folderViewMode === 'grid'
              ? 'group rounded-xl border border-slate-200 bg-white/90 hover:shadow-md hover:border-slate-300 p-4 cursor-pointer flex items-center gap-3 transition'
              : 'group border-b last:border-b-0 p-3 cursor-pointer flex items-center gap-3';
            card.className = classes;
            card.innerHTML = `
              <div class="flex h-10 w-10 items-center justify-center rounded-md bg-indigo-50 text-indigo-600">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="currentColor" viewBox="0 0 24 24"><path d="M10.414 5H20a2 2 0 0 1 2 2v1H2V7a2 2 0 0 1 2-2h5.586l.707.707L10.414 5z"/><path d="M2 9h20v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9z"/></svg>
              </div>
              <div class="flex-1 min-w-0">
                <div class="font-semibold truncate text-slate-800">${escapeHtml(name)}</div>
                <div class="text-xs text-gray-500">${escapeHtml(f)}</div>
              </div>`;
            card.addEventListener('click', () => navigateTo(f));
            els.foldersGrid.appendChild(card);
          }
        }
        if (!isRoot()) {
          renderFiles(data.files || []);
        }
      } catch (e) {
        showToast(e.message || 'Arama hatası', 'error');
      } finally {
        setStatus('');
      }
    }, 300);
    els.searchInput.addEventListener('input', onSearchInput);
  }

  // View mode controls (improved)
  // Restore persisted modes (if any)
  try { folderViewMode = sessionStorage.getItem('hisar_folder_view') || folderViewMode; } catch (e) {}
  // removed file view persistence

  function setActiveViewButtons() {
    const folderActive = 'bg-indigo-50 text-indigo-700';
    const fileActive = 'bg-indigo-50 text-indigo-700';
    // Clear folder buttons
    [els.viewGrid, els.viewList].forEach(b => {
      if (!b) return;
      b.classList.remove('bg-indigo-50', 'text-indigo-700');
      b.setAttribute('aria-pressed', 'false');
    });
    // File buttons removed
    // Set active folder button
    if (folderViewMode === 'grid' && els.viewGrid) { els.viewGrid.classList.add('bg-indigo-50', 'text-indigo-700'); els.viewGrid.setAttribute('aria-pressed','true'); }
    if (folderViewMode === 'list' && els.viewList) { els.viewList.classList.add('bg-indigo-50', 'text-indigo-700'); els.viewList.setAttribute('aria-pressed','true'); }
    // File buttons removed
  }

  function updateFileViewButtonsVisibility() { /* removed */ }

  // Folder view buttons: only re-render folders (no full navigation)
  els.viewGrid?.addEventListener('click', () => {
    folderViewMode = 'grid';
    try { sessionStorage.setItem('hisar_folder_view', folderViewMode); } catch (e) {}
    setActiveViewButtons();
    renderFolders();
  });
  els.viewList?.addEventListener('click', () => {
    folderViewMode = 'list';
    try { sessionStorage.setItem('hisar_folder_view', folderViewMode); } catch (e) {}
    setActiveViewButtons();
    renderFolders();
  });

  // File view buttons removed

  els.folderSort?.addEventListener('change', () => { renderFolders(); });
  els.fileSort?.addEventListener('change', () => { (async ()=> renderFiles(await loadFiles(currentFolder)))(); });

  // Auto logout disabled: session remains until user logs out or session expires

  // Init
  setActiveViewButtons?.();
  refresh();

  // --- Folder operation modal (moved inside IIFE) ---
  function openFolderOpModal(name) {
    const m = els.folderOpModal; if (!m) return;
    const src = (currentFolder ? `${currentFolder}/` : '') + name;
    els.folderOpSource && (els.folderOpSource.textContent = src);
    // Datalist'i allFolders ile doldur (alfabetik). Input'a varsayılan (currentFolder) ver.
    const options = (allFolders || []).slice().sort((a,b)=>a.localeCompare(b,'tr'));
    if (els.folderOpDatalist) {
      els.folderOpDatalist.innerHTML = '';
      // include root option as blank (表示 '/')
      const rootOpt = document.createElement('option'); rootOpt.value = ''; rootOpt.label = '/'; els.folderOpDatalist.appendChild(rootOpt);
      options.forEach(f => {
        const o = document.createElement('option');
        o.value = f || '';
        els.folderOpDatalist.appendChild(o);
      });
    }
    if (els.folderOpDestInput) {
      els.folderOpDestInput.value = currentFolder || '';
    }
    if (els.folderOpNewname) els.folderOpNewname.value = name;
    const radios = m.querySelectorAll('input[name="folder-op-action"]');
    radios.forEach(r=>{ r.checked = r.value === 'move'; });
    // hide/show dest input when rename is selected
    function updateDestVisibility() {
      const sel = m.querySelector('input[name="folder-op-action"]:checked')?.value;
      if (sel === 'rename') els.folderOpDestWrap?.classList.add('hidden');
      else els.folderOpDestWrap?.classList.remove('hidden');
    }
    radios.forEach(r => r.addEventListener('change', updateDestVisibility));
    updateDestVisibility();
    m.classList.remove('hidden'); m.classList.add('flex');
    function close(){ m.classList.add('hidden'); m.classList.remove('flex'); }
    const onClose = () => close();
    els.folderOpClose?.addEventListener('click', onClose, { once: true });
    els.folderOpCancel?.addEventListener('click', onClose, { once: true });
    // Confirm action
    const onConfirm = async () => {
      try {
        const actEl = m.querySelector('input[name="folder-op-action"]:checked');
        const action = (actEl && actEl.value) || 'move';
        if (action === 'rename') {
          const newName = (els.folderOpNewname?.value || '').trim();
          if (!newName || newName === name) { close(); return; }
          await renameItem(src, newName); close(); await refresh(); return;
        }
        // read destination from input (autocomplete)
        const destFolder = (els.folderOpDestInput?.value || '').trim();
        const newName = (els.folderOpNewname?.value || '').trim();
        const body = JSON.stringify({ path: src, destFolder, newName });
        const url = action === 'copy' ? '/api/copy' : '/api/move';
        await api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
        showToast(action === 'copy' ? 'Kopyalandı' : 'Taşındı', 'success');
        close(); await refresh();
      } catch (e) { showToast(e.message || 'Hata', 'error'); }
    };
    els.folderOpConfirm?.addEventListener('click', onConfirm, { once: true });
  }
 })();
