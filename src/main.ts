import { invoke, Channel } from "@tauri-apps/api/core";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "./style.css";

type Host = {
  id: string;
  name: string;
  host: string;
  port: number;
  user: string;
  auth: "password" | "key" | "agent";
  keyPath?: string;
};

const KEY = "sshache.hosts";
const $ = <T extends HTMLElement>(s: string) => document.querySelector(s) as T;

let hosts: Host[] = loadHosts();
let term: Terminal | null = null;
let fit: FitAddon | null = null;
let activeId: string | null = null;
let connected = false;
let pending: Host | null = null;
let editingId: string | null = null;

function loadHosts(): Host[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "[]");
  } catch {
    return [];
  }
}
function saveHosts() {
  localStorage.setItem(KEY, JSON.stringify(hosts));
}
function uid() {
  return Math.random().toString(36).slice(2, 9);
}

function ensureTerm() {
  if (term) return;
  term = new Terminal({
    fontFamily: 'Menlo, "SF Mono", Monaco, "Cascadia Code", monospace',
    fontSize: 13,
    cursorBlink: true,
    theme: {
      background: "#0e1116",
      foreground: "#e6edf3",
      cursor: "#4f9cf9",
      black: "#0e1116",
      brightBlack: "#8b98a5",
      red: "#f4584e",
      green: "#3fb950",
      yellow: "#d29922",
      blue: "#4f9cf9",
      magenta: "#bc8cff",
      cyan: "#39c5cf",
      white: "#e6edf3",
      brightWhite: "#ffffff",
    },
  });
  fit = new FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new WebLinksAddon());
  term.open($("#terminal"));
  fit.fit();

  term.onData((d) => {
    if (connected) invoke("ssh_write", { data: d });
  });

  const ro = new ResizeObserver(() => {
    fit?.fit();
    if (connected && term) invoke("ssh_resize", { cols: term.cols, rows: term.rows });
  });
  ro.observe($("#term-wrap"));
}

async function connect(h: Host, secret: string) {
  ensureTerm();
  $("#welcome").classList.add("hidden");
  term!.reset();
  term!.focus();
  activeId = h.id;
  connected = false;
  renderTabbar(h);
  renderList();

  const onData = new Channel<number[]>();
  onData.onmessage = (m) => term!.write(new Uint8Array(m));

  const onClose = new Channel<string>();
  onClose.onmessage = () => {
    connected = false;
    renderTabbar(h);
    renderList();
    term!.writeln("\r\n\x1b[90m— disconnected —\x1b[0m");
  };

  try {
    await invoke("ssh_connect", {
      host: h.host,
      port: h.port,
      user: h.user,
      auth: h.auth ?? "password",
      secret,
      keyPath: h.keyPath ?? "",
      cols: term!.cols,
      rows: term!.rows,
      onData,
      onClose,
    });
    connected = true;
    renderTabbar(h);
    renderList();
  } catch (e) {
    connected = false;
    renderTabbar(null);
    renderList();
    const msg = String(e);
    if (/key.?chang|chang.+key/i.test(msg)) {
      term!.writeln(
        `\r\n\x1b[1;31m⚠ HOST KEY CHANGED for ${h.host} — possible man-in-the-middle.\x1b[0m`,
      );
      term!.writeln(
        `\x1b[31mIf you trust this change, remove the stale line from ~/.ssh/known_hosts and reconnect.\x1b[0m`,
      );
    } else {
      term!.writeln(`\r\n\x1b[31mconnection failed: ${msg}\x1b[0m`);
    }
  }
}

async function disconnect() {
  await invoke("ssh_disconnect");
  connected = false;
  renderTabbar(null);
  renderList();
}

function renderTabbar(h: Host | null) {
  const bar = $("#tabbar");
  bar.innerHTML = "";
  if (!h) return;
  const label = document.createElement("span");
  label.textContent = `${h.user}@${h.host}:${h.port}`;
  bar.appendChild(label);
  if (connected) {
    const dc = document.createElement("button");
    dc.textContent = "disconnect";
    dc.style.marginLeft = "auto";
    dc.onclick = disconnect;
    bar.appendChild(dc);
  }
}

function renderList() {
  const ul = $("#host-list");
  ul.innerHTML = "";
  for (const h of hosts) {
    const li = document.createElement("li");
    li.className = "host";
    if (h.id === activeId) li.classList.add("active");
    if (h.id === activeId && connected) li.classList.add("connected");

    const dot = document.createElement("span");
    dot.className = "dot";

    const meta = document.createElement("span");
    meta.className = "meta";
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = h.name || h.host;
    const sub = document.createElement("span");
    sub.className = "sub";
    sub.textContent = `${h.user}@${h.host}:${h.port}`;
    meta.append(name, sub);

    const del = document.createElement("button");
    del.className = "del";
    del.textContent = "×";
    del.title = "Delete";
    del.onclick = (e) => {
      e.stopPropagation();
      hosts = hosts.filter((x) => x.id !== h.id);
      saveHosts();
      renderList();
    };

    const edit = document.createElement("button");
    edit.className = "edit";
    edit.textContent = "✎";
    edit.title = "Edit";
    edit.onclick = (e) => {
      e.stopPropagation();
      openHostForm(h);
    };

    li.append(dot, meta, edit, del);
    li.onclick = () => askPassword(h);
    ul.appendChild(li);
  }
}

function askPassword(h: Host) {
  pending = h;
  if ((h.auth ?? "password") === "agent") {
    // Agent supplies the secret; no prompt.
    connect(h, "");
    return;
  }
  const key = (h.auth ?? "password") === "key";
  $("#pw-title").textContent = `Connect to ${h.name || h.host}`;
  $("#pw-label").textContent = key ? "Key passphrase" : "Password";
  $("#pw-hint").textContent = key
    ? "Blank if your key has no passphrase. Not stored."
    : "Not stored. Typed per connection.";
  const form = $<HTMLFormElement>("#pw-form");
  form.reset();
  $("#pw-modal").classList.remove("hidden");
  (form.elements.namedItem("password") as HTMLInputElement).focus();
}

function openHostForm(h?: Host) {
  const form = $<HTMLFormElement>("#host-form");
  const el = (n: string) => form.elements.namedItem(n) as HTMLInputElement;
  form.reset();
  editingId = h?.id ?? null;
  $("#form-title").textContent = h ? "Edit host" : "New host";
  if (h) {
    el("name").value = h.name;
    el("host").value = h.host;
    el("port").value = String(h.port);
    el("user").value = h.user;
    el("auth").value = h.auth ?? "password";
    el("keyPath").value = h.keyPath ?? "";
  } else {
    el("port").value = "22";
  }
  $(".key-only").classList.toggle("hidden", (h?.auth ?? "password") !== "key");
  $("#modal").classList.remove("hidden");
}

function wire() {
  $("#new-host").onclick = () => openHostForm();
  $("#cancel").onclick = () => $("#modal").classList.add("hidden");
  $("#pw-cancel").onclick = () => $("#pw-modal").classList.add("hidden");

  const authSel = $<HTMLSelectElement>('#host-form select[name="auth"]');
  authSel.onchange = () =>
    $(".key-only").classList.toggle("hidden", authSel.value !== "key");

  $<HTMLFormElement>("#host-form").onsubmit = (e) => {
    e.preventDefault();
    const data = new FormData(e.target as HTMLFormElement);
    const fields = {
      name: String(data.get("name") || "").trim(),
      host: String(data.get("host")).trim(),
      port: Number(data.get("port")) || 22,
      user: String(data.get("user")).trim(),
      auth: (String(data.get("auth")) === "key"
        ? "key"
        : String(data.get("auth")) === "agent"
          ? "agent"
          : "password") as Host["auth"],
      keyPath: String(data.get("keyPath") || "").trim() || undefined,
    };
    if (editingId) {
      const i = hosts.findIndex((x) => x.id === editingId);
      if (i >= 0) hosts[i] = { ...hosts[i], ...fields };
    } else {
      hosts.push({ id: uid(), ...fields });
    }
    editingId = null;
    saveHosts();
    renderList();
    $("#modal").classList.add("hidden");
  };

  $<HTMLFormElement>("#pw-form").onsubmit = (e) => {
    e.preventDefault();
    const data = new FormData(e.target as HTMLFormElement);
    const secret = String(data.get("password"));
    $("#pw-modal").classList.add("hidden");
    if (pending) connect(pending, secret);
  };

  // Esc closes any open modal.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      $("#modal").classList.add("hidden");
      $("#pw-modal").classList.add("hidden");
    }
  });
}

wire();
renderList();
