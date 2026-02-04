/* StegoSecure SPA interactions (no frameworks) */
(function () {
  'use strict';

  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

  function setActiveNav(hash) {
    const clean = (hash || '').replace('#', '');
    $all('[data-nav]').forEach(a => {
      const target = (a.getAttribute('href') || '').replace('#', '');
      a.classList.toggle('is-active', !!clean && target === clean);
    });
  }

  function scrollToId(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
  }

  // Smooth in-page navigation
  $all('a[href^="#"]').forEach(a => {
    a.addEventListener('click', (e) => {
      const href = a.getAttribute('href');
      if (!href || href.length < 2) return;
      const id = href.slice(1);
      const el = document.getElementById(id);
      if (!el) return;
      e.preventDefault();
      history.pushState(null, '', href);
      setActiveNav(href);
      scrollToId(id);
    });
  });

  // Reveal-on-scroll animations
  function primeStagger() {
    $all('.stagger').forEach(group => {
      const kids = Array.from(group.children);
      kids.forEach((k, i) => k.style.setProperty('--i', String(i)));
    });
  }
  primeStagger();

  const revealEls = $all('.reveal');
  if (revealEls.length) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach(ent => {
        if (ent.isIntersecting) {
          ent.target.classList.add('is-in');
          io.unobserve(ent.target);
        }
      });
    }, { threshold: 0.16, rootMargin: '0px 0px -10% 0px' });
    revealEls.forEach(el => io.observe(el));
  }

  // Active nav based on current section in view
  const sections = $all('section[id]');
  if (sections.length) {
    const ioNav = new IntersectionObserver((entries) => {
      const visible = entries
        .filter(e => e.isIntersecting)
        .sort((a, b) => (a.boundingClientRect.top - b.boundingClientRect.top))[0];
      if (!visible) return;
      const id = visible.target.id;
      setActiveNav('#' + id);
    }, { threshold: 0.30, rootMargin: '-20% 0px -60% 0px' });
    sections.forEach(s => ioNav.observe(s));
  }

  // Module cards open sections
  $all('[data-open]').forEach(card => {
    card.addEventListener('click', () => {
      const target = card.getAttribute('data-open');
      if (!target) return;
      history.pushState(null, '', '#' + target);
      setActiveNav('#' + target);
      scrollToId(target);
      // If inside encode/decode panel, switch segment
      if (target === 'encode' || target === 'decode') {
        setSegment(target);
      }
    });
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        card.click();
      }
    });
  });

  // Segment control (Encode/Decode)
  const segWrap = $('[data-seg]');
  function setSegment(which) {
    const enc = $('#encode-pane');
    const dec = $('#decode-pane');
    if (!enc || !dec) return;
    const isEnc = which === 'encode';
    enc.hidden = !isEnc;
    dec.hidden = isEnc;
    $all('[data-seg-btn]').forEach(btn => {
      btn.setAttribute('aria-selected', btn.getAttribute('data-seg-btn') === which ? 'true' : 'false');
    });
  }
  if (segWrap) {
    $all('[data-seg-btn]').forEach(btn => {
      btn.addEventListener('click', () => {
        const which = btn.getAttribute('data-seg-btn');
        setSegment(which);
      });
    });
  }

  // Hash on load
  if (location.hash) {
    setActiveNav(location.hash);
    const id = location.hash.replace('#', '');
    if (id === 'encode' || id === 'decode') setSegment(id);
    // Wait for paint before scroll for smoother feel
    requestAnimationFrame(() => scrollToId(id));
  } else {
    const def = (document.body && document.body.getAttribute('data-default-seg')) || '';
    if (def === 'decode') setSegment('decode');
    else if (def === 'encode') setSegment('encode');
    else if ((location.pathname || '').toLowerCase().includes('decode')) setSegment('decode');
    else setSegment('encode');
  }

  // Encode capacity meter (already supported by backend)
  const imageInput = $('#enc-image');
  const capEl = $('#enc-capacity');
  if (imageInput && capEl) {
    imageInput.addEventListener('change', async () => {
      capEl.textContent = '';
      const f = imageInput.files && imageInput.files[0];
      if (!f) return;
      try {
        const fd = new FormData();
        fd.append('image', f);
        const r = await fetch('/encode/capacity', { method: 'POST', body: fd });
        const data = await r.json();
        if (typeof data.capacity_bytes === 'number') {
          capEl.textContent = 'Image capacity: ' + data.capacity_bytes.toLocaleString() + ' bytes';
        }
      } catch (_) {
        capEl.textContent = '';
      }
    });
  }

  const encFile = $('#enc-file');
  const encFileSize = $('#enc-file-size');
  const payloadKind = $('#enc-payload-kind');
  const encMessage = $('#enc-message');
  if (encFile && encFileSize) {
    const defaultAccept = encFile.getAttribute('accept') || '';

    function setPayloadMode(mode) {
      const isPdf = mode === 'pdf';
      if (isPdf) {
        encFile.setAttribute('accept', '.pdf');
        if (encMessage) {
          encMessage.value = '';
          encMessage.disabled = true;
          encMessage.setAttribute('aria-disabled', 'true');
        }
        encFile.required = true;
        encFileSize.textContent = 'PDF only. Select a .pdf file.';
      } else {
        encFile.setAttribute('accept', defaultAccept);
        if (encMessage) {
          encMessage.disabled = false;
          encMessage.removeAttribute('aria-disabled');
        }
        encFile.required = false;
        encFileSize.textContent = '';
      }
    }

    if (payloadKind) {
      payloadKind.addEventListener('change', () => setPayloadMode(payloadKind.value));
      setPayloadMode(payloadKind.value || 'auto');
    }

    encFile.addEventListener('change', () => {
      const f = encFile.files && encFile.files[0];
      if (!f) { encFileSize.textContent = ''; return; }
      const isPdfMode = payloadKind && payloadKind.value === 'pdf';
      const isPdf = (f.name || '').toLowerCase().endsWith('.pdf') || (f.type || '').toLowerCase() === 'application/pdf';
      if (isPdfMode && !isPdf) {
        encFile.value = '';
        encFileSize.textContent = 'Please select a .pdf file only.';
        return;
      }
      encFileSize.textContent = (isPdfMode ? 'PDF size: ' : 'File size: ') + f.size.toLocaleString() + ' bytes';
    });
  }

  function setBusy(form, busy, label) {
    const btn = form.querySelector('button[type="submit"]');
    const prog = form.querySelector('[data-progress]');
    if (btn) btn.disabled = !!busy;
    if (prog) {
      prog.hidden = !busy;
      const t = prog.querySelector('[data-progress-text]');
      if (t && label) t.textContent = label;
    }
  }

  async function submitAsSpa(form, endpoint, resultSelectorInResponse, resultMountSelector) {
    const mount = $(resultMountSelector);
    if (!mount) return;
    setBusy(form, true, endpoint.includes('encode') ? 'Encoding…' : 'Decoding…');
    mount.innerHTML = '';

    try {
      const fd = new FormData(form);
      const r = await fetch(endpoint, { method: 'POST', body: fd });
      const ct = (r.headers.get('content-type') || '').toLowerCase();
      const cd = (r.headers.get('content-disposition') || '').toLowerCase();

      // Decode endpoint sometimes returns a file (send_file). fetch() won't "download" it automatically.
      const looksLikeDownload =
        cd.includes('attachment') ||
        (!!ct && !ct.includes('text/html') && !ct.startsWith('text/'));

      if (endpoint.includes('decode') && looksLikeDownload) {
        const blob = await r.blob();
        const rawCd = r.headers.get('content-disposition') || '';
        let filename = 'extracted.bin';
        // Basic filename extraction (handles filename="x" and filename=x)
        const m = rawCd.match(/filename\*?=(?:UTF-8''|\"?)([^\";\r\n]+)/i);
        if (m && m[1]) {
          filename = decodeURIComponent(m[1].replace(/\"/g, '').trim());
        }
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1200);

        const ct2 = (r.headers.get('content-type') || '').toLowerCase();
        const isPdf = filename.toLowerCase().endsWith('.pdf') || ct2.includes('application/pdf');
        const title = isPdf ? 'PDF file successfully extracted.' : 'File extracted.';
        mount.innerHTML =
          '<div class="callout ok"><b>' + title + '</b><div class="hint">Your download should begin automatically: <span style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;">' +
          filename.replace(/</g, '&lt;').replace(/>/g, '&gt;') +
          '</span></div></div>';
      } else {
        const html = await r.text();
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const fragment = doc.querySelector(resultSelectorInResponse);
        if (fragment) {
          mount.innerHTML = fragment.innerHTML;
        } else {
          // Fallback: show a generic error if markers missing
          mount.innerHTML = '<div class="callout err"><b>Something went wrong.</b><div class="hint">Could not render server response.</div></div>';
        }
      }
    } catch (e) {
      mount.innerHTML = '<div class="callout err"><b>Network error.</b><div class="hint">Please try again.</div></div>';
    } finally {
      setBusy(form, false);
      // Keep nav and scroll position consistent
      if (endpoint.includes('encode')) {
        history.pushState(null, '', '#encode');
        setActiveNav('#encode');
      } else {
        history.pushState(null, '', '#decode');
        setActiveNav('#decode');
      }
    }
  }

  // SPA submit handlers (no reload)
  const encForm = $('#encode-form');
  if (encForm) {
    encForm.addEventListener('submit', (e) => {
      e.preventDefault();
      submitAsSpa(encForm, '/encode', '#encode-result', '#encode-result');
    });
  }
  const decForm = $('#decode-form');
  if (decForm) {
    decForm.addEventListener('submit', (e) => {
      e.preventDefault();
      submitAsSpa(decForm, '/decode', '#decode-result', '#decode-result');
    });
  }
})();

