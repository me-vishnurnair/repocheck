export function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c != null) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}
export const $ = s => document.querySelector(s);
export async function api(path, options = {}) {
  const r = await fetch(path, options);
  let d;
  try {
    d = await r.json();
  } catch {
    throw Error('The server could not respond. Try again shortly.');
  }
  if (!r.ok) {
    let msg = d.detail;
    if (Array.isArray(msg)) msg = msg.map(x => x.msg).join('; ');
    throw Error(typeof msg === 'string' ? msg : 'Request failed.');
  }
  return d;
}
export function notify(message) {
  $('#notice').textContent = message;
  clearTimeout(window.noticeTimer);
  window.noticeTimer = setTimeout(() => $('#notice').textContent = '', 5000);
}
export async function busy(button, task) {
  button.disabled = true;
  try {
    return await task();
  } catch (e) {
    notify(e.message);
  } finally {
    button.disabled = false;
  }
}
export function download(name, data, type = 'application/json') {
  const u = URL.createObjectURL(new Blob([data], {
    type
  }));
  const a = el('a', {
    href: u,
    download: name
  });
  a.click();
  setTimeout(() => URL.revokeObjectURL(u), 1000);
}
