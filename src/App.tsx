// @ts-nocheck
// SSH Ache — UI ported from the Claude Design handoff (`SSH Ache.dc.html`).
//
// The prototype's component logic is reused almost verbatim (state machine,
// renderVals, command/theme/pane/SFTP handlers); the design's templated markup
// is recreated here as JSX. Anything that needs the OS or a real socket is
// still demo-only — see docs/TASKS.md for the phase plan that wires it up.
//
// ponytail: @ts-nocheck — this is a faithful port of untyped prototype JS.
// It gets typed phase by phase as demo logic is replaced with real backend
// calls; typing it now would be churn against code that is about to change.
import * as React from "react";
import { invoke, Channel } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import logoMark from "./assets/logo-mark.svg";

type S = React.CSSProperties;

// Parse a design-style inline CSS string ("a:b;c:d") into a React style object,
// so the prototype's literal style strings port across with no hand-conversion.
const css = (str: string): S => {
  const o: any = {};
  for (const part of str.split(";")) {
    const seg = part.trim();
    if (!seg) continue;
    const i = seg.indexOf(":");
    if (i < 0) continue;
    const key = seg
      .slice(0, i)
      .trim()
      .replace(/-([a-z])/g, (_m, c) => c.toUpperCase());
    o[key] = seg.slice(i + 1).trim();
  }
  return o;
};
const norm = (x: string | S): S => (typeof x === "string" ? css(x) : x);

// Splitting an overridden `border` shorthand into longhands avoids React's
// "mixing shorthand and non-shorthand" warning when a hover/focus overlay
// changes only border-color over a base style that used the `border` shorthand.
const dedupeBorder = (st: any): S => {
  if (st.border && (st.borderColor || st.borderWidth || st.borderStyle)) {
    const m = String(st.border).match(/^(\S+)\s+(\S+)\s+(.+)$/);
    if (m) {
      if (!st.borderWidth) st.borderWidth = m[1];
      if (!st.borderStyle) st.borderStyle = m[2];
      if (!st.borderColor) st.borderColor = m[3];
    }
    delete st.border;
  }
  return st;
};

// ---- persistence: file store in Tauri, localStorage in the browser ----
const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const AUTHOR = {
  name: "Noor Ajmir Tanvir",
  github: "https://github.com/TanvirMahin24",
  email: "tanvirmahin24@gmail.com",
  site: "https://tanvirmahin.com",
  tip: "https://www.patreon.com/cw/tanvirmahin24",
  motto: "Don't be so busy making a living that you forget to actually make a life.",
};
// Open a link in the OS browser. Tauri webview won't honour target=_blank, so
// route through the open_url command there; plain window.open in the browser.
const openExt = (url: string) => {
  if (isTauri) invoke("open_url", { url }).catch(() => {});
  else window.open(url, "_blank", "noopener");
};

const loadCfg = async (name: string): Promise<string> => {
  if (isTauri) { try { return await invoke<string>("read_config", { name }); } catch (_) { return ""; } }
  try { return localStorage.getItem("sshache." + name) || ""; } catch (_) { return ""; }
};
const saveCfg = (name: string, data: string) => {
  try { localStorage.setItem("sshache." + name, data); } catch (_) {}
  if (isTauri) invoke("write_config", { name, data }).catch(() => {});
};

// Secrets live in the OS keychain (Tauri) — never in the config file or
// localStorage. Each host id maps to a JSON blob { password?, passphrase?, keyText? }.
const secretGet = async (id: string): Promise<any> => {
  if (!isTauri) return null;
  try { const s = await invoke<string>("secret_get", { id }); return s ? JSON.parse(s) : null; } catch (_) { return null; }
};
const secretSet = (id: string, obj: any) => { if (isTauri) invoke("secret_set", { id, value: JSON.stringify(obj) }).catch(() => {}); };
const secretDelete = (id: string) => { if (isTauri) invoke("secret_delete", { id }).catch(() => {}); };

// ---- encrypted backup (Web Crypto: PBKDF2-SHA256 → AES-256-GCM) ----
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const ub64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const deriveKey = async (password: string, salt: Uint8Array) => {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
};
const encryptJson = async (obj: any, password: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return JSON.stringify({ app: "ssh-ache", v: 1, kdf: "PBKDF2-SHA256", iter: 200000, salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ct)) });
};
const decryptJson = async (envelope: string, password: string) => {
  const e = JSON.parse(envelope);
  const key = await deriveKey(password, ub64(e.salt));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(e.iv) }, key, ub64(e.ct));
  return JSON.parse(new TextDecoder().decode(pt));
};

// MCP server (local agent access). Fixed loopback port + a random bearer token.
const MCP_PORT = 8765;
const MCP_URL = `http://127.0.0.1:${MCP_PORT}/mcp`;
const genToken = () => Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, "0")).join("");

// Vault-lock passphrase: store a PBKDF2 hash (salt + derived bits), verify on unlock.
const hashPass = async (password: string, saltB64?: string) => {
  const salt = saltB64 ? ub64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" }, base, 256);
  return { salt: b64(salt), hash: b64(new Uint8Array(bits)) };
};

// Reproduces the design framework's `style-hover` / `style-focus` pseudo-styles
// that plain React inline styles can't express.
function Hov(props: any) {
  const { s, h, f, as = "div", children, onFocus, onBlur, ...rest } = props;
  const [hov, setHov] = React.useState(false);
  const [foc, setFoc] = React.useState(false);
  const Tag: any = as;
  const style: S = dedupeBorder({
    ...norm(s),
    ...(hov && h ? norm(h) : {}),
    ...(foc && f ? norm(f) : {}),
  });
  const isVoid = as === "input";
  return (
    <Tag
      {...rest}
      style={style}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      onFocus={(e: any) => {
        if (f) setFoc(true);
        if (onFocus) onFocus(e);
      }}
      onBlur={(e: any) => {
        if (f) setFoc(false);
        if (onBlur) onBlur(e);
      }}
    >
      {isVoid ? null : children}
    </Tag>
  );
}

// Sidebar folder row: hover reveals a favourite star (left) and an edit icon
// (right); a favourited folder shows the star permanently.
function FolderRow({ folder }: any) {
  const [h, setH] = React.useState(false);
  const showStar = folder.favorite || h;
  return (
    <div onClick={folder.onSelect} onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)} style={folder.style}>
      <span onClick={(e) => { e.stopPropagation(); folder.onToggleFav(); }} title="Favorite folder"
        style={{ width: "13px", flex: "none", textAlign: "center", fontSize: "11px", cursor: "pointer", color: folder.favorite ? "#ffcf5c" : "#6a6a74", opacity: showStar ? 1 : 0 }}>
        {folder.favorite ? "★" : "☆"}
      </span>
      <span style={{ fontSize: "11px", flex: "none", width: "14px", textAlign: "center", color: folder.color }}>▸</span>
      <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{folder.name}</span>
      {h ? (
        <span onClick={(e) => { e.stopPropagation(); folder.onEdit(); }} title="Edit folder" style={{ flex: "none", fontSize: "11px", cursor: "pointer", color: "#9a9aa3" }}>✎</span>
      ) : (
        <span style={{ flex: "none", fontSize: "10px", color: folder.countColor }}>{folder.count}</span>
      )}
    </div>
  );
}

// Map a theme to an xterm 16-colour palette. bg/fg/cursor track the theme and
// `blue` is tinted with the accent. ponytail: the rest is a fixed dark ANSI set
// — per-theme ANSI palettes would need colour data the design themes don't carry.
const xtermTheme = (t: any) => {
  const a = t.ansi || [];
  return {
    background: t.bg,
    foreground: t.fg,
    cursor: t.accent,
    cursorAccent: t.bg,
    selectionBackground: "rgba(255,255,255,0.18)",
    black: a[0] || "#0e1116", red: a[1] || "#f4584e", green: a[2] || "#3fb950", yellow: a[3] || "#d29922",
    blue: a[4] || t.accent, magenta: a[5] || "#bc8cff", cyan: a[6] || "#39c5cf", white: a[7] || t.fg,
    brightBlack: a[8] || "#8b98a5", brightRed: a[9] || "#ff6b62", brightGreen: a[10] || "#56d364", brightYellow: a[11] || "#e3b341",
    brightBlue: a[12] || t.accent, brightMagenta: a[13] || "#d2a8ff", brightCyan: a[14] || "#56d4dd", brightWhite: a[15] || "#ffffff",
  };
};
const cursorStyleOf = (c: string) => (c === "bar" ? "bar" : c === "underline" ? "underline" : "block");

// A live SSH pane: a real xterm.js terminal wired to the russh backend over a
// per-pane sessionId. Created once on mount; disconnected + disposed on unmount.
// In a plain browser (no Tauri runtime) it shows a hint instead of connecting.
function TermPane({ session, theme, fontSize, cursor, scrollback, onConnected, onError, onClosed, onHostKey, register }: any) {
  const wrapRef = React.useRef<any>(null);
  const inst = React.useRef<any>(null);

  React.useEffect(() => {
    const term = new Terminal({
      fontFamily: "'JetBrains Mono', ui-monospace, monospace",
      fontSize,
      cursorBlink: true,
      cursorStyle: cursorStyleOf(cursor),
      scrollback: scrollback || 1000,
      theme: xtermTheme(theme),
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(wrapRef.current);
    try { fit.fit(); } catch (_) {}
    term.focus();
    inst.current = { term, fit };
    if (register) register(session.sessionId, { clear: () => term.clear() });

    const h = session.host || {};
    const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
    if (!isTauri) {
      term.writeln("\x1b[33mTerminal backend only runs inside the desktop app — start it with `npm run tauri dev`.\x1b[0m");
      if (onConnected) onConnected();
      return () => { if (register) register(session.sessionId, null); term.dispose(); };
    }

    let disposed = false;

    if (session.kind === "local") {
      const onDataL = new Channel<number[]>();
      onDataL.onmessage = (m) => term.write(new Uint8Array(m));
      const onCloseL = new Channel<string>();
      onCloseL.onmessage = () => { term.writeln("\r\n\x1b[90m— shell exited —\x1b[0m"); if (onClosed) onClosed(); };
      invoke("pty_spawn", { id: session.sessionId, cols: term.cols, rows: term.rows, onData: onDataL, onClose: onCloseL })
        .then(() => { if (!disposed && onConnected) onConnected(); })
        .catch((e) => { term.writeln(`\r\n\x1b[31mlocal shell failed: ${String(e)}\x1b[0m`); if (onError) onError(String(e)); });
      const dataSubL = term.onData((d) => { invoke("pty_write", { id: session.sessionId, data: d }).catch(() => {}); });
      const roL = new ResizeObserver(() => { try { fit.fit(); invoke("pty_resize", { id: session.sessionId, cols: term.cols, rows: term.rows }).catch(() => {}); } catch (_) {} });
      roL.observe(wrapRef.current);
      return () => {
        disposed = true;
        if (register) register(session.sessionId, null);
        roL.disconnect();
        dataSubL.dispose();
        invoke("pty_close", { id: session.sessionId }).catch(() => {});
        term.dispose();
      };
    }

    term.writeln(`\x1b[90m→ connecting ${h.user || ""}@${h.addr}:${h.port || 22}…\x1b[0m`);
    const onData = new Channel<number[]>();
    onData.onmessage = (m) => term.write(new Uint8Array(m));
    const onClose = new Channel<string>();
    onClose.onmessage = () => { term.writeln("\r\n\x1b[90m— disconnected —\x1b[0m"); if (onClosed) onClosed(); };

    invoke("ssh_connect", {
      sessionId: session.sessionId,
      host: h.addr,
      port: Number(h.port) || 22,
      user: h.user || "root",
      auth: h.auth || "password",
      secret: session.secret || "",
      keyPath: h.keyPath || "",
      keyText: session.keyText || "",
      cols: term.cols,
      rows: term.rows,
      onData,
      onClose,
    })
      .then(() => { if (!disposed && onConnected) onConnected(); })
      .catch((e) => {
        if (disposed) return;
        const msg = String(e);
        if (msg.indexOf("UNKNOWN_HOST") === 0) {
          const parts = msg.split(""); // ["UNKNOWN_HOST", fingerprint, openssh-key]
          term.writeln("\r\n\x1b[33m→ first time connecting to this host — confirm the key fingerprint to continue.\x1b[0m");
          if (onHostKey) onHostKey(parts[1] || "", parts[2] || "");
          return;
        }
        if (msg === "KEY_CHANGED" || /key.?chang|chang.+key/i.test(msg)) {
          term.writeln(`\r\n\x1b[1;31m⚠ HOST KEY CHANGED for ${h.addr} — possible man-in-the-middle.\x1b[0m`);
          term.writeln(`\x1b[31mRemove the stale ~/.ssh/known_hosts line if you trust the change, then reconnect.\x1b[0m`);
          if (onError) onError("host key changed for " + h.addr);
          return;
        }
        term.writeln(`\r\n\x1b[31mconnection failed: ${msg}\x1b[0m`);
        if (onError) onError(msg);
      });

    const dataSub = term.onData((d) => { invoke("ssh_write", { sessionId: session.sessionId, data: d }).catch(() => {}); });
    const ro = new ResizeObserver(() => {
      try { fit.fit(); invoke("ssh_resize", { sessionId: session.sessionId, cols: term.cols, rows: term.rows }).catch(() => {}); } catch (_) {}
    });
    ro.observe(wrapRef.current);

    return () => {
      disposed = true;
      if (register) register(session.sessionId, null);
      ro.disconnect();
      dataSub.dispose();
      invoke("ssh_disconnect", { sessionId: session.sessionId }).catch(() => {});
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Live-apply theme / font / cursor / scrollback changes without re-mounting.
  React.useEffect(() => {
    const i = inst.current;
    if (!i) return;
    i.term.options.theme = xtermTheme(theme);
    i.term.options.fontSize = fontSize;
    i.term.options.cursorStyle = cursorStyleOf(cursor);
    i.term.options.scrollback = scrollback || 1000;
    try { i.fit.fit(); } catch (_) {}
  }, [theme.bg, theme.fg, theme.accent, fontSize, cursor, scrollback]);

  return <div ref={wrapRef} style={{ flex: 1, minHeight: 0, overflow: "hidden", padding: "6px 8px", background: theme.bg }} />;
}

export default class App extends React.Component<any, any> {
  paneWrap = React.createRef();
  paletteRef = React.createRef();
  inputRefs = {};
  termApis = {};
  registerTerm = (id, api) => { if (api) this.termApis[id] = api; else delete this.termApis[id]; };
  uid = 100;
  _drag = null;

  THEMES = {
    ember:     { name:'Ember',      author:'ssh-ache',  downloads:'48.2k', bg:'#0c0b0a', fg:'#efe7e1', fgDim:'#b9aaa0', accent:'#ff7a59', sw:['#ff7a59','#ffb38a','#e0d4cc','#8a7d75','#211a16'], ansi:['#211a16','#ff6b62','#8fbf6a','#ffb86c','#ff9d7a','#d9a07a','#c9b8a8','#efe7e1','#8a7d75','#ff8d70','#a6d189','#ffd0a0','#ffb38a','#e0b89a','#e0d4cc','#ffffff'] },
    tokyo:     { name:'Tokyo Storm', author:'enkia',    downloads:'212k',  bg:'#1a1b26', fg:'#c0caf5', fgDim:'#7a82a8', accent:'#7aa2f7', sw:['#7aa2f7','#bb9af7','#7dcfff','#9ece6a','#f7768e'], ansi:['#1d202f','#f7768e','#9ece6a','#e0af68','#7aa2f7','#bb9af7','#7dcfff','#a9b1d6','#414868','#f7768e','#9ece6a','#e0af68','#7aa2f7','#bb9af7','#7dcfff','#c0caf5'] },
    catppuccin:{ name:'Mocha',      author:'catppuccin',downloads:'301k',  bg:'#1e1e2e', fg:'#cdd6f4', fgDim:'#8a8fb3', accent:'#f5c2e7', sw:['#f5c2e7','#cba6f7','#89dceb','#a6e3a1','#f38ba8'], ansi:['#45475a','#f38ba8','#a6e3a1','#f9e2af','#89b4fa','#f5c2e7','#94e2d5','#bac2de','#585b70','#f38ba8','#a6e3a1','#f9e2af','#89b4fa','#f5c2e7','#94e2d5','#a6adc8'] },
    gruvbox:   { name:'Gruvbox',    author:'morhetz',   downloads:'176k',  bg:'#282828', fg:'#ebdbb2', fgDim:'#a89984', accent:'#fabd2f', sw:['#fabd2f','#fe8019','#b8bb26','#83a598','#fb4934'], ansi:['#282828','#cc241d','#98971a','#d79921','#458588','#b16286','#689d6a','#a89984','#928374','#fb4934','#b8bb26','#fabd2f','#83a598','#d3869b','#8ec07c','#ebdbb2'] },
    nord:      { name:'Nord',       author:'arctic',    downloads:'264k',  bg:'#2e3440', fg:'#e5e9f0', fgDim:'#9aa3b5', accent:'#88c0d0', sw:['#88c0d0','#81a1c1','#a3be8c','#b48ead','#bf616a'], ansi:['#3b4252','#bf616a','#a3be8c','#ebcb8b','#81a1c1','#b48ead','#88c0d0','#e5e9f0','#4c566a','#bf616a','#a3be8c','#ebcb8b','#81a1c1','#b48ead','#8fbcbb','#eceff4'] },
    dracula:   { name:'Dracula',    author:'zeno',      downloads:'289k',  bg:'#282a36', fg:'#f8f8f2', fgDim:'#9ea3c0', accent:'#bd93f9', sw:['#bd93f9','#ff79c6','#8be9fd','#50fa7b','#ff5555'], ansi:['#21222c','#ff5555','#50fa7b','#f1fa8c','#bd93f9','#ff79c6','#8be9fd','#f8f8f2','#6272a4','#ff6e6e','#69ff94','#ffffa5','#d6acff','#ff92df','#a4ffff','#ffffff'] },
    ayu:       { name:'Ayu Mirage', author:'dempfi',    downloads:'94.1k', bg:'#1f2430', fg:'#cbccc6', fgDim:'#8b8f9a', accent:'#ffcc66', sw:['#ffcc66','#ffd580','#bae67e','#5ccfe6','#f28779'], ansi:['#191e2a','#ed8274','#a6cc70','#fad07b','#6dcbfa','#cfbafa','#90e1c6','#c7c7c7','#686868','#f28779','#bae67e','#ffd580','#73d0ff','#d4bfff','#95e6cb','#ffffff'] },
    rosepine:  { name:'Rosé Pine',  author:'rose-pine', downloads:'118k',  bg:'#191724', fg:'#e0def4', fgDim:'#908caa', accent:'#ebbcba', sw:['#ebbcba','#c4a7e7','#9ccfd8','#31748f','#eb6f92'], ansi:['#26233a','#eb6f92','#31748f','#f6c177','#9ccfd8','#c4a7e7','#ebbcba','#e0def4','#6e6a86','#eb6f92','#31748f','#f6c177','#9ccfd8','#c4a7e7','#ebbcba','#e0def4'] }
  };

  SEED_HOSTS = [
    { id:'h1', name:'production-web', user:'root',     addr:'10.0.4.21',         port:'22',   folder:'Production', tags:['web','nginx','prod'],   auth:'key',      online:true,  lastUsed:'2h ago'  },
    { id:'h2', name:'db-primary',     user:'postgres', addr:'10.0.4.40',         port:'22',   folder:'Databases',  tags:['postgres','prod'],      auth:'key',      online:true,  lastUsed:'5h ago'  },
    { id:'h3', name:'edge-cache',     user:'deploy',   addr:'192.168.1.8',       port:'2222', folder:'Edge',       tags:['redis','cache'],        auth:'password', online:false, lastUsed:'3d ago'  },
    { id:'h4', name:'staging',        user:'ubuntu',   addr:'staging.internal',  port:'22',   folder:'Production', tags:['web','staging'],        auth:'key',      online:true,  lastUsed:'1d ago', fail:true },
    { id:'h5', name:'raspberrypi',    user:'pi',       addr:'raspberrypi.local', port:'22',   folder:'Personal',   tags:['iot','arm'],            auth:'password', online:true,  lastUsed:'1w ago'  },
    { id:'h6', name:'backup-nas',     user:'admin',    addr:'192.168.1.20',      port:'22',   folder:'Personal',   tags:['storage','smb'],        auth:'password', online:false, lastUsed:'never'   }
  ];

  state = {
    sidebarOpen: true,
    sftpOpen: false,
    paletteOpen: false,
    themesOpen: false,
    aboutOpen: false,
    paletteQuery: '',
    themeId: 'ember',
    view: 'dashboard',
    search: '',
    activeFolder: 'all',
    activeTags: [],
    addHostOpen: false,
    settingsOpen: false,
    editingId: null,
    newHostId: null,
    hosts: this.SEED_HOSTS,
    form: { name:'', host:'', port:'22', user:'', auth:'password', password:'', keyMode:'file', keyPath:'', keyText:'', passphrase:'', folder:'', tagInput:'', tags:[] },
    settings: { fontSize:13, cursor:'block', scrollback:'10000', confirmClose:true, restoreTabs:true, lockIdle:false },
    activeTabId: 't1',
    activePaneId: 'p1',
    connecting: null,
    secretPrompt: null,
    hostKeyPrompt: null,
    confirmClose: null,
    ioPrompt: null,
    locked: false,
    lockPrompt: null,
    unlockValue: '',
    fwdPrompt: null,
    forwards: [],
    folderMeta: {},
    folderEdit: null,
    mcpRunning: false,
    mcpLog: [],
    mcpOpen: false,
    approvalReq: null,
    transfer: null,
    dragOver: null,
    toasts: [],
    localFiles: [],
    remoteFiles: [],
    localPath: '',
    remotePath: '',
    sftpId: null,
    sftpStatus: 'idle', // idle | connecting | ready | error
    sftpErr: '',
    conflict: null,
    conflictAll: false,
    conflictPolicy: null, // null | 'replace' | 'skip' (set by "Apply to all")
    queue: [],
    selLocal: [],
    selRemote: [],
    tabs: [
      { id:'t1', title:'production-web', host:'production-web', user:'root', addr:'10.0.4.21', layout:'row', sizes:[100], panes:[
        { id:'p1', user:'root', host:'production-web', cwd:'~', input:'', lines:[
          { t:'sys', x:'SSH Ache 0.4.0 · terminal session' },
          { t:'ok',  x:'● secure channel established · root@10.0.4.21 (production-web)' },
          { t:'cmd', x:'❯ uptime' },
          { t:'out', x:' 14:22:07 up 37 days,  load average: 0.18, 0.22, 0.20' },
          { t:'cmd', x:'❯ ls' },
          { t:'out', x:'src   assets   Cargo.toml   README.md   build.rs' },
          { t:'dim', x:'type `help` for commands · ⌘K palette · ⌘T themes · ⌘D split' }
        ] }
      ] }
    ]
  };

  // On-device persistence. Synchronous localStorage hydrate on construct (works
  // in the browser preview and as a Tauri migration source); componentDidMount
  // then loads the authoritative on-disk file in the desktop app. Sessions
  // (tabs/panes) stay ephemeral. Secrets are never part of this blob.
  constructor(props) {
    super(props);
    const d = this._loadSync();
    if (d) this.state = { ...this.state, ...this._merge(this.state, d) };
  }
  _loadSync() {
    try {
      const raw = localStorage.getItem('sshache.state') || localStorage.getItem('sshache.v04');
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }
  _merge(base, d) {
    return {
      hosts: Array.isArray(d.hosts) ? d.hosts : base.hosts,
      settings: { ...base.settings, ...(d.settings || {}) },
      themeId: this.THEMES[d.themeId] ? d.themeId : base.themeId,
      sidebarOpen: typeof d.sidebarOpen === 'boolean' ? d.sidebarOpen : base.sidebarOpen,
      folderMeta: (d.folderMeta && typeof d.folderMeta === 'object') ? d.folderMeta : base.folderMeta,
    };
  }

  componentDidMount() {
    this._key = (e) => {
      const meta = e.metaKey || e.ctrlKey;
      const k = (e.key || '').toLowerCase();
      if (meta && k === 'k') { e.preventDefault(); this.setState(s => ({ paletteOpen: !s.paletteOpen, paletteQuery: '' })); }
      else if (meta && k === 't') { e.preventDefault(); this.setState(s => ({ themesOpen: !s.themesOpen })); }
      else if (meta && k === 'd') { e.preventDefault(); this.splitRight(); }
      else if (meta && k === 'b') { e.preventDefault(); this.setState(s => ({ sidebarOpen: !s.sidebarOpen })); }
      else if (meta && k === 'j') { e.preventDefault(); this.toggleSftp(); }
      else if (meta && k === 'n') { e.preventDefault(); this.openAddHost(); }
      else if (meta && k === '1') { e.preventDefault(); this.setState({ view: 'dashboard' }); }
      else if (meta && k === '2') { e.preventDefault(); this.setState({ view: 'workspace' }); }
      else if (k === 'escape') { this.setState({ paletteOpen: false, themesOpen: false, addHostOpen: false, settingsOpen: false, aboutOpen: false }); }
    };
    window.addEventListener('keydown', this._key);
    // Authoritative load from the on-disk store (Tauri); redundant in browser.
    loadCfg('state').then(raw => {
      if (!raw) return;
      let d;
      try { d = JSON.parse(raw); } catch (e) { return; }
      this.setState(s => this._merge(s, d), () => this.maybeRestore(d));
    });
    // Idle vault-lock: lock after 15 min of no interaction when enabled + set.
    this._lastActivity = Date.now();
    this._activity = () => { this._lastActivity = Date.now(); };
    window.addEventListener('mousemove', this._activity);
    window.addEventListener('keydown', this._activity);
    window.addEventListener('mousedown', this._activity);
    this._idle = setInterval(() => {
      const st = this.state.settings;
      if (st.lockIdle && st.lockHash && !this.state.locked && (Date.now() - this._lastActivity) > 15 * 60 * 1000) {
        this.setState({ locked: true });
      }
    }, 20000);
    // MCP: poll status + listen for per-command approval requests from the server.
    if (isTauri) {
      this.refreshMcp();
      import('@tauri-apps/api/event').then(({ listen }) => { listen('mcp-approval', (e) => this.setState({ approvalReq: e.payload })); }).catch(() => {});
    }
  }
  componentWillUnmount() {
    window.removeEventListener('keydown', this._key);
    window.removeEventListener('mousemove', this._activity);
    window.removeEventListener('keydown', this._activity);
    window.removeEventListener('mousedown', this._activity);
    clearTimeout(this._ct); clearInterval(this._tr); clearInterval(this._idle);
  }
  hashAndSetLock = async (pw) => {
    if (!pw) return;
    const { salt, hash } = await hashPass(pw);
    this.setState(s => ({ settings: { ...s.settings, lockIdle: true, lockSalt: salt, lockHash: hash }, lockPrompt: null }));
    this.pushToast({ type: 'ok', title: 'Vault lock enabled', msg: 'Locks after 15 min idle' });
  };
  tryUnlock = async (pw) => {
    const st = this.state.settings;
    const { hash } = await hashPass(pw || '', st.lockSalt);
    if (hash === st.lockHash) { this._lastActivity = Date.now(); this.setState({ locked: false, unlockValue: '' }); }
    else this.pushToast({ type: 'err', title: 'Wrong passphrase', msg: 'Try again' });
  };
  lockNow = () => {
    if (this.state.settings.lockHash) this.setState({ locked: true });
    else this.setState({ lockPrompt: { mode: 'set', value: '' } });
  };

  // ---- local port forwarding (-L) ----
  startForward() {
    if (!isTauri) { this.pushToast({ type: 'info', title: 'Port forward', msg: 'Available in the desktop app.' }); return; }
    const tab = this.state.tabs.find(t => t.id === this.state.activeTabId);
    const pane = tab && tab.panes.find(p => p.live && (p.kind || 'ssh') === 'ssh');
    if (!pane) { this.pushToast({ type: 'info', title: 'Port forward', msg: 'Open an SSH connection first.' }); return; }
    this.setState({ fwdPrompt: { localPort: '', remoteHost: '127.0.0.1', remotePort: '', sessionId: pane.sessionId, host: pane.host, secret: pane.secret, keyText: pane.keyText }, paletteOpen: false });
  }
  setFwd = (k, val) => this.setState(s => ({ fwdPrompt: s.fwdPrompt ? { ...s.fwdPrompt, [k]: val } : null }));
  submitForward = () => {
    const f = this.state.fwdPrompt;
    if (!f) return;
    const lp = parseInt(f.localPort, 10), rp = parseInt(f.remotePort, 10);
    if (!lp || !rp || !f.remoteHost.trim()) { this.pushToast({ type: 'err', title: 'Invalid forward', msg: 'Need local port, remote host, and remote port.' }); return; }
    const h = f.host, label = `localhost:${lp} → ${f.remoteHost.trim()}:${rp}`, id = f.sessionId + ':fwd:' + lp;
    this.setState({ fwdPrompt: null });
    invoke('forward_start', { id, host: h.addr, port: Number(h.port) || 22, user: h.user || 'root', auth: h.auth || 'password', secret: f.secret || '', keyPath: h.keyPath || '', keyText: f.keyText || '', localPort: lp, remoteHost: f.remoteHost.trim(), remotePort: rp })
      .then(() => { this.setState(s => ({ forwards: [...s.forwards, { id, sessionId: f.sessionId, label }] })); this.pushToast({ type: 'ok', title: 'Port forward started', msg: label }); })
      .catch((e) => this.pushToast({ type: 'err', title: 'Forward failed', msg: String(e) }));
  };
  stopForwardsFor = (sids) => {
    if (!sids || !sids.length) return;
    const keep = [], drop = [];
    this.state.forwards.forEach(fw => (sids.includes(fw.sessionId) ? drop : keep).push(fw));
    if (!drop.length) return;
    drop.forEach(fw => { if (isTauri) invoke('forward_stop', { id: fw.id }).catch(() => {}); });
    this.setState({ forwards: keep });
  };
  stopAllForwards = () => {
    const n = this.state.forwards.length;
    this.state.forwards.forEach(fw => { if (isTauri) invoke('forward_stop', { id: fw.id }).catch(() => {}); });
    this.setState({ forwards: [] });
    this.pushToast({ type: 'info', title: 'Port forwards stopped', msg: n ? `${n} closed` : 'none active' });
  };

  // ---- MCP server (local agent access) ----
  ensureMcpToken() {
    let t = this.state.settings.mcpToken;
    if (!t) { t = genToken(); this.setSetting('mcpToken', t); }
    return t;
  }
  refreshMcp() {
    if (!isTauri) return;
    invoke('mcp_status').then((s) => this.setState({ mcpRunning: !!s.running, mcpLog: Array.isArray(s.log) ? s.log : [] })).catch(() => {});
  }
  openMcp() { this.setState({ mcpOpen: true, settingsOpen: false }); this.refreshMcp(); }
  toggleMcp = () => {
    if (!isTauri) { this.pushToast({ type: 'info', title: 'MCP', msg: 'Available in the desktop app.' }); return; }
    if (this.state.mcpRunning) { invoke('mcp_stop').then(() => this.setState({ mcpRunning: false })).catch(() => {}); return; }
    const token = this.ensureMcpToken();
    invoke('mcp_start', { token, port: MCP_PORT }).then(() => this.setState({ mcpRunning: true })).catch((e) => this.pushToast({ type: 'err', title: 'MCP failed to start', msg: String(e) }));
  };
  mcpRespond = (allow) => {
    const r = this.state.approvalReq;
    if (!r) return;
    if (isTauri) invoke('mcp_approval_respond', { id: r.id, allow }).catch(() => {});
    this.setState({ approvalReq: null });
    if (allow) setTimeout(() => this.refreshMcp(), 600);
  };
  toggleHostAgent(id) {
    this.setState(s => ({ hosts: s.hosts.map(h => h.id === id ? { ...h, agentAllowed: !h.agentAllowed } : h) }));
  }
  componentDidUpdate(prevProps, prevState) {
    if (this.state.paletteOpen && !prevState.paletteOpen && this.paletteRef.current) {
      this.paletteRef.current.focus();
    }
    const openHosts = (st) => Array.from(new Set(st.tabs.flatMap(t => t.panes.filter(p => p.live).map(p => p.host && p.host.id)).filter(Boolean)));
    const keys = ['hosts', 'settings', 'themeId', 'sidebarOpen', 'folderMeta'];
    const cur = openHosts(this.state);
    if (keys.some(k => this.state[k] !== prevState[k]) || JSON.stringify(cur) !== JSON.stringify(openHosts(prevState))) {
      saveCfg('state', JSON.stringify({
        hosts: this.state.hosts, settings: this.state.settings,
        themeId: this.state.themeId, sidebarOpen: this.state.sidebarOpen,
        folderMeta: this.state.folderMeta, openHosts: cur,
      }));
    }
  }

  genId() { this.uid += 1; return 'x' + this.uid; }

  // Frameless-window controls (Tauri only; no-op in the browser preview).
  winAction(a) {
    if (!isTauri) return;
    const w = getCurrentWindow();
    if (a === 'min') w.minimize();
    else if (a === 'max') w.toggleMaximize();
    else w.close();
  }

  pushToast(t) {
    const id = this.genId();
    this.setState(s => ({ toasts: [...s.toasts, { ...t, id }] }));
    setTimeout(() => this.setState(s => ({ toasts: s.toasts.filter(x => x.id !== id) })), 3600);
  }

  _localTab() {
    // A real local shell (PTY) tab.
    const id = this.genId(), pid = this.genId();
    return { id, title: 'localhost', host: 'localhost', user: 'you', addr: 'shell', layout: 'row', sizes: [100], panes: [
      { id: pid, live: true, kind: 'local', sessionId: pid, host: { addr: 'localhost', user: 'you' }, user: 'you', hostName: 'localhost', cwd: '~' }
    ] };
  }

  newTab() {
    const t = this._localTab();
    this.setState(s => ({ tabs:[...s.tabs, t], activeTabId:t.id, activePaneId:t.panes[0].id }));
  }
  closeTab(id, force) {
    const tab = this.state.tabs.find(t => t.id === id);
    const live = !!(tab && tab.panes.some(p => p.live));
    if (!force && live && this.state.settings.confirmClose) {
      this.setState({ confirmClose: { tabId: id, name: tab.title } });
      return;
    }
    if (tab) this.stopForwardsFor(tab.panes.filter(p => p.live).map(p => p.sessionId));
    this.setState(s => this._closeTabState(s, id));
  }
  confirmCloseTab = () => {
    const c = this.state.confirmClose;
    this.setState({ confirmClose: null });
    if (c) this.closeTab(c.tabId, true);
  };
  // On launch, silently reconnect previously-open hosts that have a remembered
  // secret (or use the agent); skip any that would need an interactive prompt.
  async maybeRestore(d) {
    if (!isTauri || !this.state.settings.restoreTabs || !Array.isArray(d.openHosts)) return;
    for (const hid of d.openHosts) {
      const host = this.state.hosts.find(h => h.id === hid);
      if (!host) continue;
      const auth = host.auth || 'password';
      let secret = '', keyText = '';
      if (auth !== 'agent') {
        const saved = await secretGet(host.id);
        keyText = saved && saved.keyText ? saved.keyText : '';
        const v = saved ? (auth === 'key' ? saved.passphrase : saved.password) : undefined;
        const has = (x) => x !== undefined && x !== null;
        if (auth === 'key') { if (!keyText && !has(v)) continue; secret = has(v) ? v : ''; }
        else { if (!has(v)) continue; secret = v; }
      }
      this.beginConnect(host, secret, true, keyText);
    }
  }
  _closeTabState(s, tabId) {
    const tabs = s.tabs.filter(t => t.id !== tabId);
    if (tabs.length === 0) { const nt = this._localTab(); return { tabs:[nt], activeTabId:nt.id, activePaneId:nt.panes[0].id }; }
    let activeTabId = s.activeTabId, activePaneId = s.activePaneId;
    if (s.activeTabId === tabId) { const nt = tabs[tabs.length - 1]; activeTabId = nt.id; activePaneId = nt.panes[0].id; }
    return { tabs, activeTabId, activePaneId };
  }

  addPane(dir) {
    this.setState(s => {
      const tabs = s.tabs.map(t => {
        if (t.id !== s.activeTabId) return t;
        if (t.panes.length >= 4) return t;
        const src = t.panes.find(p => p.id === s.activePaneId) || t.panes[0];
        let np;
        if (src.live) {
          // Splitting a live session opens a second, independent shell to the
          // same host (its own sessionId → its own backend SSH session).
          const nid = this.genId();
          np = { id: nid, live: true, kind: src.kind || 'ssh', sessionId: nid, host: src.host, secret: src.secret, keyText: src.keyText, user: src.user, hostName: src.hostName, cwd: src.cwd };
        } else {
          np = { id: this.genId(), user: src.user, host: src.host, cwd: src.cwd, input: '', lines: [
            { t: 'sys', x: 'SSH Ache — new pane' },
            { t: 'ok', x: '● ' + src.user + '@' + src.host }
          ] };
        }
        const panes = [...t.panes, np];
        const sizes = panes.map(() => 100 / panes.length);
        return { ...t, layout:dir, panes, sizes };
      });
      return { tabs };
    });
  }
  splitRight = () => this.addPane('row');
  splitDown = () => this.addPane('col');

  closePaneById(id) {
    this.setState(s => {
      const t = s.tabs.find(x => x.id === s.activeTabId);
      if (!t) return {};
      if (t.panes.length > 1) {
        const panes = t.panes.filter(p => p.id !== id);
        const sizes = panes.map(() => 100 / panes.length);
        return { tabs: s.tabs.map(x => x.id === t.id ? { ...x, panes, sizes } : x), activePaneId: panes[0].id };
      }
      return this._closeTabState(s, t.id);
    });
  }

  clearActive() {
    const tab = this.state.tabs.find(t => t.id === this.state.activeTabId);
    const pane = tab && tab.panes.find(p => p.id === this.state.activePaneId);
    if (pane && pane.live) { const api = this.termApis[pane.sessionId]; if (api) api.clear(); return; }
    this.setState(s => ({ tabs: s.tabs.map(t => t.id === s.activeTabId ? { ...t, panes: t.panes.map(p => p.id === s.activePaneId ? { ...p, lines: [] } : p) } : t) }));
  }

  evalCmd(cmd) {
    const c = cmd.split(/\s+/)[0];
    if (c === '') return [];
    if (c === 'clear' || c === 'cls') return null;
    if (c === 'help') return [
      { t:'out', x:'commands:' },
      { t:'dim', x:'  help   ls    pwd    whoami   date   echo' },
      { t:'dim', x:'  neofetch   theme   sftp   split   clear   exit' }
    ];
    if (c === 'ls' || c === 'll' || c === 'dir') return [
      { t:'out', x:'drwxr-xr-x  deploy  4.0K  src/' },
      { t:'out', x:'drwxr-xr-x  deploy  4.0K  assets/' },
      { t:'out', x:'-rw-r--r--  deploy  1.2K  Cargo.toml' },
      { t:'out', x:'-rw-r--r--  deploy  4.8K  README.md' },
      { t:'out', x:'-rwxr-xr-x  deploy  0.6K  build.rs' }
    ];
    if (c === 'pwd') return [{ t:'out', x:'/home/root' }];
    if (c === 'whoami') return [{ t:'out', x:'root' }];
    if (c === 'date') return [{ t:'out', x:new Date().toString() }];
    if (c === 'echo') return [{ t:'out', x:cmd.slice(5) }];
    if (c === 'neofetch' || c === 'fetch') return [
      { t:'accent', x:'   ┌─┐┌─┐┬ ┬  ┌─┐┌─┐┬ ┬┌─┐' },
      { t:'accent', x:'   └─┐└─┐├─┤  ├─┤│  ├─┤├┤ ' },
      { t:'accent', x:'   └─┘└─┘┴ ┴  ┴ ┴└─┘┴ ┴└─┘' },
      { t:'dim', x:'' },
      { t:'out', x:'  os      SSH Ache 0.4.0' },
      { t:'out', x:'  shell   zsh 5.9' },
      { t:'out', x:'  term    truecolor · 256 themes' },
      { t:'out', x:'  cloud   none — fully offline' },
      { t:'out', x:'  uptime  37 days' }
    ];
    if (c === 'theme' || c === 'themes') return [{ t:'ok', x:'opening theme browser…' }];
    if (c === 'sftp') return [{ t:'ok', x:'opening SFTP panel…' }];
    if (c === 'split') return [{ t:'ok', x:'splitting pane → ⌘D' }];
    if (c === 'exit' || c === 'logout') return [{ t:'dim', x:'(session preserved locally)' }];
    if (c === 'sudo') return [{ t:'err', x:'sudo: a password is required' }];
    return [{ t:'err', x: c + ': command not found — try `help`' }];
  }

  runCommand(paneId, raw) {
    const cmd = (raw || '').trim();
    const out = this.evalCmd(cmd);
    this.setState(s => ({
      tabs: s.tabs.map(t => ({ ...t, panes: t.panes.map(p => {
        if (p.id !== paneId) return p;
        if (out === null) return { ...p, lines: [], input: '' };
        return { ...p, lines: [...p.lines, { t:'cmd', x:'❯ ' + cmd }, ...out], input: '' };
      }) }))
    }));
    const c = cmd.split(/\s+/)[0];
    if (c === 'theme' || c === 'themes') setTimeout(() => this.setState({ themesOpen: true }), 130);
    else if (c === 'sftp') setTimeout(() => this.setState({ sftpOpen: true }), 130);
    else if (c === 'split') setTimeout(() => this.splitRight(), 130);
  }

  startResize(idx, e) {
    e.preventDefault(); e.stopPropagation();
    const s = this.state;
    const tab = s.tabs.find(t => t.id === s.activeTabId);
    if (!tab) return;
    const layout = tab.layout;
    const wrap = this.paneWrap.current;
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    const total = layout === 'row' ? rect.width : rect.height;
    const startPos = layout === 'row' ? e.clientX : e.clientY;
    const sizes = [...tab.sizes];
    const min = 12;
    const move = (ev) => {
      const cur = layout === 'row' ? ev.clientX : ev.clientY;
      let d = (cur - startPos) / total * 100;
      let a = sizes[idx - 1] + d, b = sizes[idx] - d;
      if (a < min) { b -= (min - a); a = min; }
      if (b < min) { a -= (min - b); b = min; }
      const ns = [...sizes]; ns[idx - 1] = a; ns[idx] = b;
      this.setState(st => ({ tabs: st.tabs.map(t => t.id === tab.id ? { ...t, sizes: ns } : t) }));
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
      document.body.style.cursor = '';
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    document.body.style.cursor = layout === 'row' ? 'col-resize' : 'row-resize';
  }

  // ---- connect flow (real SSH) ----
  // password / key auth need a secret → prompt first; agent connects directly.
  // The live tab's TermPane runs ssh_connect and reports back through the pane
  // callbacks (handlePaneConnected / handlePaneError).
  async connectHost(host) {
    if (this.state.connecting) return;
    const auth = host.auth || 'password';
    if (auth === 'agent') { this.beginConnect(host, '', false, ''); return; }
    // Use remembered secrets from the keychain if present; otherwise prompt.
    const saved = await secretGet(host.id);
    const keyText = saved && saved.keyText ? saved.keyText : '';
    const has = (x) => x !== undefined && x !== null;
    if (auth === 'key') {
      // A pasted key with no passphrase still connects; otherwise saved/prompt.
      if (keyText && !has(saved && saved.passphrase)) { this.beginConnect(host, '', false, keyText); return; }
      if (saved && has(saved.passphrase)) { this.beginConnect(host, saved.passphrase, false, keyText); return; }
      this.setState({ secretPrompt: { host, kind: auth, value: '', keyText }, paletteOpen: false });
      return;
    }
    if (saved && has(saved.password)) { this.beginConnect(host, saved.password, false, ''); return; }
    this.setState({ secretPrompt: { host, kind: auth, value: '' }, paletteOpen: false });
  }
  submitSecret = () => {
    const sp = this.state.secretPrompt;
    if (!sp) return;
    this.setState({ secretPrompt: null });
    this.beginConnect(sp.host, sp.value, false, sp.keyText || '');
  };
  cancelSecret = () => this.setState({ secretPrompt: null });
  beginConnect(host, secret, silent, keyText) {
    const id = this.genId(), pid = this.genId();
    const tab = { id, title: host.name, host: host.name, user: host.user, addr: host.addr, layout: 'row', sizes: [100], panes: [
      { id: pid, live: true, kind: 'ssh', sessionId: pid, host, secret, keyText: keyText || '', user: host.user, hostName: host.name, cwd: '~' }
    ] };
    this.setState(s => ({ tabs: [...s.tabs, tab], activeTabId: id, activePaneId: pid, view: 'workspace', paletteOpen: false, ...(silent ? {} : { connecting: { host, secret, tabId: id, failed: false, step: 0 } }) }));
  }
  // Flip a pane's live-connection flag (drives the orange dot on the tab).
  setPaneConnected(tabId, paneId, val) {
    this.setState(s => ({ tabs: s.tabs.map(t => t.id === tabId ? { ...t, panes: t.panes.map(p => p.id === paneId ? { ...p, connected: val } : p) } : t) }));
  }
  handlePaneConnected(tab, paneId) {
    this.setPaneConnected(tab.id, paneId, true);
    const c = this.state.connecting;
    if (c && c.tabId === tab.id) {
      this.setState({ connecting: null });
      this.pushToast({ type: 'ok', title: 'Connected', msg: c.host.user + '@' + c.host.addr });
    }
  }
  handlePaneClosed(tab, paneId) { this.setPaneConnected(tab.id, paneId, false); }
  handlePaneError(tab, paneId, msg) {
    this.setPaneConnected(tab.id, paneId, false);
    const c = this.state.connecting;
    if (c && c.tabId === tab.id) {
      this.setState(s => ({ connecting: s.connecting ? { ...s.connecting, failed: true } : null }));
      clearTimeout(this._ct);
      this._ct = setTimeout(() => { this.setState({ connecting: null }); this.closeTab(tab.id, true); }, 1300);
    }
    this.pushToast({ type: 'err', title: 'Connection failed', msg: msg.length > 90 ? msg.slice(0, 90) + '…' : msg });
  }
  // First-seen host key: pause, show the fingerprint, let the user decide.
  handleHostKey(tab, fp, key) {
    const c = this.state.connecting;
    if (!c) return;
    this.setState({ connecting: null, hostKeyPrompt: { host: c.host, secret: c.secret, tabId: tab.id, fp, key } });
  }
  acceptHostKey = () => {
    const hk = this.state.hostKeyPrompt;
    if (!hk) return;
    this.setState({ hostKeyPrompt: null });
    this.closeTab(hk.tabId, true);
    const proceed = () => this.beginConnect(hk.host, hk.secret);
    if (isTauri) {
      invoke('trust_host', { host: hk.host.addr, port: Number(hk.host.port) || 22, key: hk.key })
        .then(proceed)
        .catch((e) => this.pushToast({ type: 'err', title: 'Could not trust host', msg: String(e) }));
    } else { proceed(); }
  };
  rejectHostKey = () => {
    const hk = this.state.hostKeyPrompt;
    if (!hk) return;
    this.setState({ hostKeyPrompt: null });
    this.closeTab(hk.tabId, true);
    this.pushToast({ type: 'info', title: 'Connection cancelled', msg: hk.host.name });
  };
  cancelConnect = () => {
    const c = this.state.connecting;
    clearTimeout(this._ct);
    this.setState({ connecting: null });
    if (c && c.tabId) this.closeTab(c.tabId, true);
  };

  // ---- SFTP transfer queue (multi-file / folder drag-drop) ----
  toggleSel(side, name) {
    const key = side === 'local' ? 'selLocal' : 'selRemote';
    this.setState(s => { const cur = s[key]; return { [key]: cur.includes(name) ? cur.filter(n => n !== name) : [...cur, name] }; });
  }
  // Drop onto the opposite pane: enqueue the dragged item(s) and start draining.
  sftpDrop(targetSide) {
    const d = this._drag;
    this._drag = null;
    this.setState({ dragOver: null });
    if (!d || d.side === targetSide) return;
    const dir = targetSide === 'remote' ? 'up' : 'down';
    const items = (d.items || []).filter(it => it && it.name && it.name !== '..');
    if (!items.length) return;
    this.setState(s => ({ queue: [...s.queue, ...items.map(file => ({ file, dir }))] }), () => this.processQueue());
  }
  processQueue() {
    if (this.state.transfer || this.state.conflict || !this.state.sftpId) return;
    const q = this.state.queue;
    // Batch drained: forget any "apply to all" choice so the next drop prompts again.
    if (!q.length) { if (this.state.conflictPolicy || this.state.conflictAll) this.setState({ conflictPolicy: null, conflictAll: false }); return; }
    const next = q[0];
    this.setState({ queue: q.slice(1) }, () => {
      const { file, dir } = next;
      const destList = dir === 'up' ? this.state.remoteFiles : this.state.localFiles;
      const exists = destList.some(e => e.name === file.name);
      if (exists) {
        const policy = this.state.conflictPolicy;
        if (policy === 'skip') { this.pushToast({ type: 'info', title: 'Skipped', msg: file.name }); this.processQueue(); return; }
        if (policy !== 'replace') { this.setState({ conflict: { file, dir }, conflictAll: false }); return; }
      }
      this.doTransfer(file, dir);
    });
  }
  resolveConflict = (action) => {
    const c = this.state.conflict;
    if (!c) return;
    const all = this.state.conflictAll;
    this.setState({ conflict: null, conflictAll: false, conflictPolicy: all ? action : this.state.conflictPolicy }, () => {
      if (action === 'replace') this.doTransfer(c.file, c.dir);
      else { this.pushToast({ type: 'info', title: 'Skipped', msg: c.file.name }); this.processQueue(); }
    });
  };
  // One transfer (file or recursive folder), progress streamed via a Channel.
  doTransfer(file, dir) {
    if (this.state.transfer || !this.state.sftpId) return;
    const id = this.state.sftpId;
    const join = (a, b) => (a.endsWith('/') ? a : a + '/') + b;
    const localFull = join(this.state.localPath, file.name);
    const remoteFull = join(this.state.remotePath, file.name);
    const isDir = file.kind === 'dir';
    this.setState({ transfer: { name: file.name, pct: 0, dir } });
    const onProgress = new Channel();
    onProgress.onmessage = (p) => this.setState(s => (s.transfer ? { transfer: { ...s.transfer, pct: p } } : {}));
    const cmd = dir === 'up' ? (isDir ? 'sftp_put_dir' : 'sftp_put') : (isDir ? 'sftp_get_dir' : 'sftp_get');
    const args = dir === 'up'
      ? { id, localPath: localFull, remotePath: remoteFull, onProgress }
      : { id, remotePath: remoteFull, localPath: localFull, onProgress };
    invoke(cmd, args).then(() => {
      this.pushToast({ type: 'ok', title: dir === 'up' ? 'Uploaded' : 'Downloaded', msg: file.name });
      if (dir === 'up') this.listRemote(this.state.remotePath); else this.listLocal(this.state.localPath);
      this.setState({ transfer: null }, () => this.processQueue());
    }).catch((e) => {
      this.pushToast({ type: 'err', title: 'Transfer failed', msg: String(e) });
      this.setState({ transfer: null }, () => this.processQueue());
    });
  }

  // ---- SFTP panel ----
  toggleSftp() {
    if (this.state.sftpOpen) { this.closeSftp(); return; }
    this.setState({ sftpOpen: true }, () => this.openSftp());
  }
  closeSftp() {
    const id = this.state.sftpId;
    if (id && isTauri) invoke('sftp_disconnect', { id }).catch(() => {});
    this.setState({ sftpOpen: false, sftpId: null, sftpStatus: 'idle', transfer: null, conflict: null, conflictAll: false, conflictPolicy: null });
  }
  openSftp() {
    const tab = this.state.tabs.find(t => t.id === this.state.activeTabId);
    const pane = tab && tab.panes.find(p => p.live && (p.kind || 'ssh') === 'ssh');
    if (!isTauri) { this.setState({ sftpStatus: 'error', sftpErr: 'SFTP runs in the desktop app (npm run tauri dev).' }); return; }
    if (!pane) { this.setState({ sftpStatus: 'error', sftpErr: 'Open an SSH connection first, then reopen SFTP.' }); return; }
    const id = tab.id + ':sftp';
    const h = pane.host;
    this.setState({ sftpStatus: 'connecting', sftpErr: '', sftpId: id, localFiles: [], remoteFiles: [], conflict: null, conflictAll: false, conflictPolicy: null });
    invoke('sftp_connect', { id, host: h.addr, port: Number(h.port) || 22, user: h.user || 'root', auth: h.auth || 'password', secret: pane.secret || '', keyPath: h.keyPath || '' })
      .then(async (home) => {
        const lhome = await invoke('local_home');
        this.setState({ sftpStatus: 'ready', remotePath: home, localPath: lhome });
        this.listLocal(lhome);
        this.listRemote(home);
      })
      .catch((e) => this.setState({ sftpStatus: 'error', sftpErr: String(e) }));
  }
  listLocal(path) {
    invoke('local_list', { path }).then((files) => this.setState({ localFiles: files, localPath: path, selLocal: [] })).catch((e) => this.setState({ sftpErr: String(e) }));
  }
  listRemote(path) {
    const id = this.state.sftpId;
    if (!id) return;
    invoke('sftp_list', { id, path }).then((files) => this.setState({ remoteFiles: files, remotePath: path, selRemote: [] })).catch((e) => this.setState({ sftpErr: String(e) }));
  }

  // ---- encrypted import / export ----
  // Export bundles hosts + settings + keychain secrets, encrypts with the user's
  // password (AES-256-GCM), and writes to a chosen file. Import reverses it.
  async exportConfig() {
    if (!isTauri) { this.pushToast({ type: 'info', title: 'Export', msg: 'Available in the desktop app.' }); return; }
    this.setState({ ioPrompt: { mode: 'export', value: '' } });
  }
  async importConfig() {
    if (!isTauri) { this.pushToast({ type: 'info', title: 'Import', msg: 'Available in the desktop app.' }); return; }
    const { open } = await import('@tauri-apps/plugin-dialog');
    const path = await open({ multiple: false, filters: [{ name: 'SSH Ache backup', extensions: ['json'] }] });
    if (!path || typeof path !== 'string') return;
    this.setState({ ioPrompt: { mode: 'import', value: '', path } });
  }
  ioCancel = () => this.setState({ ioPrompt: null });
  async ioSubmit() {
    const io = this.state.ioPrompt;
    if (!io || !io.value) { this.pushToast({ type: 'err', title: 'Password required', msg: 'Enter a password.' }); return; }
    this.setState({ ioPrompt: null });
    if (io.mode === 'export') {
      const { save } = await import('@tauri-apps/plugin-dialog');
      const path = await save({ defaultPath: 'ssh-ache-backup.json', filters: [{ name: 'SSH Ache backup', extensions: ['json'] }] });
      if (!path) return;
      try {
        const secrets = {};
        for (const h of this.state.hosts) { const s = await secretGet(h.id); if (s) secrets[h.id] = s; }
        const bundle = { kind: 'ssh-ache-backup', state: { hosts: this.state.hosts, settings: this.state.settings, themeId: this.state.themeId }, secrets };
        const envelope = await encryptJson(bundle, io.value);
        await invoke('write_file', { path, data: envelope });
        this.pushToast({ type: 'ok', title: 'Exported (encrypted)', msg: String(path) });
      } catch (e) {
        this.pushToast({ type: 'err', title: 'Export failed', msg: String(e) });
      }
    } else {
      try {
        const envelope = await invoke('read_file', { path: io.path });
        const bundle = await decryptJson(envelope, io.value);
        if (!bundle || bundle.kind !== 'ssh-ache-backup') throw new Error('not a backup');
        const st = bundle.state || {};
        this.setState((s) => this._merge(s, st));
        if (bundle.secrets) for (const id of Object.keys(bundle.secrets)) secretSet(id, bundle.secrets[id]);
        const n = Array.isArray(st.hosts) ? st.hosts.length : 0;
        this.pushToast({ type: 'ok', title: 'Imported', msg: n + ' host' + (n === 1 ? '' : 's') + ' restored' });
      } catch (e) {
        this.pushToast({ type: 'err', title: 'Import failed', msg: 'Wrong password or invalid file.' });
      }
    }
  }

  setView(v) { this.setState({ view: v, paletteOpen: false }); }

  openAddHost() {
    this.setState({ addHostOpen: true, settingsOpen: false, paletteOpen: false, editingId: null,
      form: { name:'', host:'', port:'22', user:'', auth:'password', password:'', keyMode:'file', keyPath:'', keyText:'', passphrase:'', folder:'', tagInput:'', tags:[] } });
  }
  openEditHost(h) {
    this.setState({ addHostOpen: true, settingsOpen: false, paletteOpen: false, editingId: h.id,
      form: { name:h.name, host:h.addr, port:h.port, user:h.user, auth:h.auth, password:'',
        keyMode: h.keyMode || 'file', keyPath: h.keyPath || '', keyText: h.keyText || '', passphrase:'',
        folder:h.folder, tagInput:'', tags:[...h.tags] } });
  }
  // Build an `ssh` command line for use in another terminal / tool.
  sshCommand(h) {
    const parts = ['ssh'];
    if (h.port && String(h.port) !== '22') parts.push('-p', String(h.port));
    if ((h.auth || 'password') === 'key' && h.keyPath) parts.push('-i', h.keyPath);
    parts.push((h.user || 'root') + '@' + h.addr);
    return parts.join(' ');
  }
  copyCommand(h) {
    const cmd = this.sshCommand(h);
    const ok = () => this.pushToast({ type: 'ok', title: 'Command copied', msg: cmd });
    try {
      navigator.clipboard.writeText(cmd).then(ok).catch(() => this.pushToast({ type: 'info', title: 'Copy this command', msg: cmd }));
    } catch (e) {
      this.pushToast({ type: 'info', title: 'Copy this command', msg: cmd });
    }
  }
  closeAddHost() { this.setState({ addHostOpen: false, editingId: null }); }
  setField(key, val) { this.setState(s => ({ form: { ...s.form, [key]: val } })); }
  addTagFromInput() {
    this.setState(s => {
      const v = (s.form.tagInput || '').trim().toLowerCase().replace(/\s+/g, '-');
      if (!v || s.form.tags.includes(v)) return { form: { ...s.form, tagInput: '' } };
      return { form: { ...s.form, tags: [...s.form.tags, v], tagInput: '' } };
    });
  }
  removeTag(t) { this.setState(s => ({ form: { ...s.form, tags: s.form.tags.filter(x => x !== t) } })); }

  validateKey(raw) {
    const text = (raw || '').trim();
    if (!text) return { state:'empty', type:'', message:'Paste a private key or certificate' };
    const pub = /^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/]+={0,3}(\s+\S+)?$/;
    if (pub.test(text)) return { state:'valid', type:'OpenSSH public key', message:'Valid OpenSSH public key' };
    const begin = text.match(/^-----BEGIN ([A-Z0-9 ]+)-----/);
    const end = text.match(/-----END ([A-Z0-9 ]+)-----\s*$/);
    if (!begin) return { state:'error', type:'', message:'Missing "-----BEGIN …-----" header line' };
    if (!end) return { state:'error', type:'', message:'Missing "-----END …-----" footer line' };
    if (begin[1] !== end[1]) return { state:'error', type:'', message:'BEGIN/END labels differ — ' + begin[1] + ' vs ' + end[1] };
    const label = begin[1];
    const inner = text.replace(/-----BEGIN [A-Z0-9 ]+-----/, '').replace(/-----END [A-Z0-9 ]+-----/, '');
    const lines = inner.split(/\r?\n/).map(l => l.trim()).filter(l => l.length && !/^[A-Za-z][A-Za-z0-9-]*:/.test(l));
    const b64 = lines.join('');
    if (b64.length < 32) return { state:'error', type:'', message:'Key body looks truncated (too short)' };
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return { state:'error', type:'', message:'Key body has invalid base64 characters' };
    try { atob(b64); } catch (e) { return { state:'error', type:'', message:'Key body is not valid base64 (check for missing lines)' }; }
    const names = {
      'OPENSSH PRIVATE KEY':'OpenSSH private key', 'RSA PRIVATE KEY':'RSA private key',
      'EC PRIVATE KEY':'EC private key', 'DSA PRIVATE KEY':'DSA private key',
      'PRIVATE KEY':'PKCS#8 private key', 'ENCRYPTED PRIVATE KEY':'encrypted PKCS#8 key',
      'CERTIFICATE':'X.509 certificate', 'PUBLIC KEY':'public key'
    };
    const type = names[label] || ('PEM block (' + label + ')');
    return { state:'valid', type, message:'Valid ' + type };
  }

  // Pull the secret fields out of the form; null when nothing to store.
  _formSecrets(f) {
    const s: any = {};
    if (f.auth === 'password' && f.password) s.password = f.password;
    if (f.auth === 'key' && f.passphrase) s.passphrase = f.passphrase;
    if (f.auth === 'key' && f.keyMode === 'text' && f.keyText.trim()) s.keyText = f.keyText;
    return Object.keys(s).length ? s : null;
  }
  saveHost() {
    const f = this.state.form;
    if (!f.name.trim() || !f.host.trim()) {
      this.pushToast({ type:'err', title:'Missing fields', msg:'Name and host/IP are required' });
      return;
    }
    if (f.auth === 'key' && f.keyMode === 'text' && f.keyText.trim() && this.validateKey(f.keyText).state === 'error') {
      this.pushToast({ type:'err', title:'Invalid key', msg: this.validateKey(f.keyText).message });
      return;
    }
    // Non-secret fields only — keyText / password / passphrase go to the keychain.
    const base = {
      name: f.name.trim(), user: (f.user.trim() || 'root'), addr: f.host.trim(),
      port: (f.port.trim() || '22'), folder: (f.folder.trim() || 'Uncategorized'),
      tags: f.tags, auth: f.auth, keyMode: f.keyMode, keyPath: f.keyPath
    };
    const secrets = this._formSecrets(f);
    if (this.state.editingId) {
      const id = this.state.editingId;
      this.setState(s => ({ hosts: s.hosts.map(h => h.id === id ? { ...h, ...base } : h), addHostOpen: false, editingId: null, newHostId: id }));
      if (secrets) secretSet(id, secrets);
      this.pushToast({ type:'ok', title:'Host updated', msg: base.name + ' · ' + base.user + '@' + base.addr });
      setTimeout(() => this.setState(s => (s.newHostId === id ? { newHostId: null } : {})), 2200);
      return;
    }
    const id = this.genId();
    const host = { id, ...base, online: true, lastUsed: 'never' };
    this.setState(s => ({ hosts: [...s.hosts, host], addHostOpen: false, editingId: null, view: 'dashboard', activeFolder: 'all', search: '', activeTags: [], newHostId: id }));
    if (secrets) secretSet(id, secrets);
    this.pushToast({ type:'ok', title:'Host added', msg: host.name + ' · ' + host.user + '@' + host.addr });
    setTimeout(() => this.setState(s => (s.newHostId === id ? { newHostId: null } : {})), 2200);
  }
  deleteHost(id) {
    const h = this.state.hosts.find(x => x.id === id);
    this.setState(s => ({ hosts: s.hosts.filter(x => x.id !== id), addHostOpen: false, editingId: null }));
    secretDelete(id);
    this.pushToast({ type:'err', title:'Host removed', msg: h ? h.name : '' });
  }

  openSettings() { this.setState({ settingsOpen: true, addHostOpen: false, paletteOpen: false }); }
  closeSettings() { this.setState({ settingsOpen: false }); }
  setSetting(key, val) { this.setState(s => ({ settings: { ...s.settings, [key]: val } })); }

  setSearch(v) { this.setState({ search: v }); }
  setFolder(f) { this.setState({ activeFolder: f, view: 'dashboard' }); }
  toggleTag(t) {
    this.setState(s => ({ activeTags: s.activeTags.includes(t) ? s.activeTags.filter(x => x !== t) : [...s.activeTags, t] }));
  }

  // ---- folder colour / favourites ----
  toggleFolderFav(name) {
    this.setState(s => { const m = { ...(s.folderMeta[name] || {}) }; m.favorite = !m.favorite; return { folderMeta: { ...s.folderMeta, [name]: m } }; });
  }
  toggleHostFav(id) {
    this.setState(s => ({ hosts: s.hosts.map(h => h.id === id ? { ...h, favorite: !h.favorite } : h) }));
  }
  openFolderEdit(name) {
    const m = this.state.folderMeta[name] || {};
    this.setState({ folderEdit: { name, newName: name, color: m.color || '', favorite: !!m.favorite } });
  }
  setFolderEdit(k, v) { this.setState(s => ({ folderEdit: s.folderEdit ? { ...s.folderEdit, [k]: v } : null })); }
  saveFolderEdit() {
    const fe = this.state.folderEdit;
    if (!fe) return;
    const oldName = fe.name, newName = (fe.newName || '').trim() || oldName;
    this.setState(s => {
      let hosts = s.hosts, folderMeta = { ...s.folderMeta }, activeFolder = s.activeFolder;
      if (newName !== oldName) {
        hosts = s.hosts.map(h => h.folder === oldName ? { ...h, folder: newName } : h);
        delete folderMeta[oldName];
        if (activeFolder === oldName) activeFolder = newName;
      }
      folderMeta[newName] = { color: fe.color || '', favorite: !!fe.favorite };
      return { hosts, folderMeta, folderEdit: null, activeFolder };
    });
    this.pushToast({ type: 'ok', title: 'Folder updated', msg: newName });
  }

  renderVals() {
    const s = this.state;
    const theme = this.THEMES[s.themeId];
    const activeTab = s.tabs.find(t => t.id === s.activeTabId) || s.tabs[0];
    const layout = activeTab ? activeTab.layout : 'row';

    const lineColor = (t) => ({ cmd: theme.accent, out: theme.fg, dim: '#5c5c66', sys: '#7e7e88', ok: '#46d9a0', err: '#ff6b78', accent: theme.accent }[t] || theme.fg);

    const mkPanes = (tab) => tab.panes.map((p, i) => {
      const sizes = tab.sizes || [];
      const flex = sizes[i] || (100 / tab.panes.length);
      const active = p.id === s.activePaneId && tab.id === s.activeTabId;
      const tlayout = tab.layout;
      return {
        id: p.id, idx: i, notFirst: i > 0, active,
        cwd: p.cwd, input: p.input,
        hostLabel: p.live ? (p.user + '@' + (p.host && p.host.addr ? p.host.addr : (p.hostName || ''))) : (p.user + '@' + p.host),
        promptUser: p.user + '@' + p.host,
        promptColor: theme.accent,
        live: !!p.live, kind: p.kind || 'ssh', sessionId: p.sessionId, hostObj: p.live ? p.host : null, secret: p.secret, keyText: p.keyText,
        termTheme: { bg: theme.bg, fg: theme.fg, accent: theme.accent, ansi: theme.ansi }, fontSize: s.settings.fontSize,
        cursor: s.settings.cursor, scrollback: parseInt(s.settings.scrollback, 10) || 1000,
        onConnected: () => this.handlePaneConnected(tab, p.id), onError: (msg) => this.handlePaneError(tab, p.id, msg),
        onClosed: () => this.handlePaneClosed(tab, p.id),
        onHostKey: (fp, key) => this.handleHostKey(tab, fp, key),
        boxStyle: { position:'relative', flexGrow:flex, flexShrink:1, flexBasis:0, minWidth:0, minHeight:0, display:'flex', flexDirection:'column', background:theme.bg, border:'1px solid ' + (active ? 'rgba(255,122,89,.4)' : '#1a1a20'), borderRadius:'7px', overflow:'hidden', boxShadow: active ? '0 0 0 1px rgba(255,122,89,.12)' : 'none', transition:'border-color .15s ease' },
        gutterStyle: tlayout === 'row'
          ? { position:'absolute', left:'-5px', top:0, width:'10px', height:'100%', cursor:'col-resize', zIndex:5 }
          : { position:'absolute', top:'-5px', left:0, height:'10px', width:'100%', cursor:'row-resize', zIndex:5 },
        headStyle: { display:'flex', alignItems:'center', gap:'8px', padding:'7px 10px', borderBottom:'1px solid ' + (active ? 'rgba(255,122,89,.16)' : '#16161c'), background:'rgba(0,0,0,.2)', flex:'none' },
        termStyle: { flex:1, overflow:'auto', padding:'10px 13px 13px', color:theme.fg, caretColor:theme.accent, fontSize:s.settings.fontSize + 'px', lineHeight:'1.55', background:theme.bg },
        lines: (p.lines || []).map(l => ({ display: (l.x === '' ? ' ' : l.x), color: lineColor(l.t) })),
        onActivate: () => { this.setState({ activePaneId: p.id }); const el = this.inputRefs[p.id]; if (el) setTimeout(() => el.focus(), 0); },
        onInput: (e) => { const v = e.target.value; this.setState(st => ({ tabs: st.tabs.map(t => t.id === tab.id ? { ...t, panes: t.panes.map(pp => pp.id === p.id ? { ...pp, input: v } : pp) } : t) })); },
        onKey: (e) => { if (e.key === 'Enter') { e.preventDefault(); this.runCommand(p.id, e.target.value); } },
        onClose: (e) => { e.stopPropagation(); this.closePaneById(p.id); },
        onGutterDown: (e) => this.startResize(i, e),
        setRef: (el) => { this.inputRefs[p.id] = el; }
      };
    });
    const panes = activeTab ? mkPanes(activeTab) : [];
    // Every tab's panes stay mounted; inactive tabs are hidden so their SSH/PTY
    // sessions (and xterm scrollback) survive a tab switch — only closeTab kills them.
    const tabPanes = s.tabs.map(t => ({
      id: t.id, active: t.id === s.activeTabId,
      wrapStyle: t.id === s.activeTabId
        ? { flex:1, minWidth:0, minHeight:0, display:'flex', flexDirection: t.layout === 'row' ? 'row' : 'column', gap:'8px' }
        : { display:'none' },
      panes: mkPanes(t),
    }));

    const tabs = s.tabs.map(t => {
      const sel = t.id === s.activeTabId;                                 // selected tab → outline + shadow
      const conn = t.panes.some(p => p.live && p.connected);             // any live pane connected → orange dot
      return {
      id: t.id, title: t.title, active: sel,
      style: { display:'flex', alignItems:'center', gap:'8px', padding:'0 8px 0 11px', height:'30px', borderRadius:'6px', cursor:'pointer', fontSize:'12px', color: sel ? '#ededf0' : '#8b8b95', background: sel ? '#15151b' : 'transparent', border:'1px solid ' + (sel ? 'rgba(255,122,89,.45)' : 'transparent'), boxShadow: sel ? '0 0 0 1px rgba(255,122,89,.12), 0 2px 9px rgba(0,0,0,.4)' : 'none', maxWidth:'170px', flex:'none' },
      dotStyle: { width:'7px', height:'7px', borderRadius:'50%', background: conn ? '#ff7a59' : '#3a3a44', flex:'none' },
      onSelect: () => this.setState({ activeTabId: t.id, activePaneId: t.panes[0].id }),
      onClose: (e) => { e.stopPropagation(); this.closeTab(t.id); }
    };});

    const themesList = Object.keys(this.THEMES).map(id => {
      const th = this.THEMES[id];
      const active = id === s.themeId;
      return {
        id, name: th.name, author: th.author, downloads: th.downloads, bg: th.bg, fg: th.fg, accent: th.accent, sw: th.sw, active,
        cardStyle: { padding:'12px', background:'#101015', border:'1px solid ' + (active ? 'rgba(255,122,89,.45)' : '#1e1e26'), borderRadius:'10px', cursor:'pointer', transition:'border-color .15s ease', boxShadow: active ? '0 0 0 1px rgba(255,122,89,.1)' : 'none' },
        onApply: () => { this.setState({ themeId: id }); this.pushToast({ type:'ok', title:'Theme applied', msg: th.name + ' · by ' + th.author }); }
      };
    });

    // command palette
    const baseItems = [
      { name:'Add host', hint:'⌘N', icon:'+', color:'#ff7a59', run: () => this.openAddHost() },
      { name:'Open dashboard', hint:'⌘1', icon:'⊞', color:'#6ea8ff', run: () => this.setState({ view:'dashboard' }) },
      { name:'Open terminal', hint:'⌘2', icon:'›_', color:'#46d9a0', run: () => this.setState({ view:'workspace' }) },
      { name:'Settings', hint:'', icon:'⚙', color:'#9a9aa3', run: () => this.openSettings() },
      { name:'New tab', hint:'shell', icon:'+', color:'#6ea8ff', run: () => this.newTab() },
      { name:'Split right', hint:'⌘D', icon:'▢', color:'#ff7a59', run: () => this.splitRight() },
      { name:'Split down', hint:'', icon:'▢', color:'#ff7a59', run: () => this.splitDown() },
      { name:'Close pane', hint:'', icon:'×', color:'#ff6b78', run: () => this.closePaneById(this.state.activePaneId) },
      { name:'Browse themes', hint:'⌘T', icon:'◐', color:'#bd93f9', run: () => this.setState({ themesOpen: true }) },
      { name:'Open SFTP panel', hint:'⌘J', icon:'⇅', color:'#46d9a0', run: () => this.setState({ sftpOpen: true }, () => this.openSftp()) },
      { name:'Toggle sidebar', hint:'⌘B', icon:'▤', color:'#9a9aa3', run: () => this.setState(st => ({ sidebarOpen: !st.sidebarOpen })) },
      { name:'Clear terminal', hint:'', icon:'⌫', color:'#9a9aa3', run: () => this.clearActive() },
      { name:'Lock now', hint:'', icon:'⚿', color:'#ff7a59', run: () => this.lockNow() },
      { name:'Add port forward', hint:'-L', icon:'⇄', color:'#46d9a0', run: () => this.startForward() },
      { name:'Stop port forwards', hint:'', icon:'⊘', color:'#ff6b78', run: () => this.stopAllForwards() }
    ];
    const hostItems = s.hosts.map(h => ({ name:'Connect — ' + h.name, hint:h.addr, icon:'›', color:'#ff7a59', run: () => this.connectHost(h) }));
    const allItems = [...baseItems, ...hostItems];
    const q = s.paletteQuery.toLowerCase();
    const paletteItems = allItems
      .filter(it => it.name.toLowerCase().includes(q) || (it.hint || '').toLowerCase().includes(q))
      .map(it => ({ name: it.name, hint: it.hint, icon: it.icon, iconColor: it.color, onRun: () => { it.run(); this.setState({ paletteOpen: false }); } }));

    // files
    const joinPath = (a, b) => (a === '/' ? '' : (a || '').replace(/\/+$/, '')) + '/' + b;
    const parentPath = (p) => { const t = (p || '/').replace(/\/+$/, ''); const i = t.lastIndexOf('/'); return i <= 0 ? '/' : t.slice(0, i); };
    const navTo = (side, path) => { if (side === 'local') this.listLocal(path); else this.listRemote(path); };
    const selOf = (side) => (side === 'local' ? s.selLocal : s.selRemote);
    const rowStyle = (isDir, selected) => ({ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 8px', borderRadius: '5px', cursor: isDir ? 'pointer' : 'grab', fontSize: '11.5px', color: selected ? '#ededf0' : '#c7c7cf', background: selected ? 'rgba(255,122,89,.14)' : 'transparent' });
    const mkFile = (f, side) => {
      const isDir = f.kind === 'dir';
      const base = side === 'local' ? s.localPath : s.remotePath;
      const selected = selOf(side).includes(f.name);
      return {
        name: f.name, isDir, selected, isUp: false,
        glyph: isDir ? '▸' : '◦', glyphColor: isDir ? '#ff7a59' : '#54545e',
        sub: isDir ? 'dir' : (f.size || ''),
        rowStyle: rowStyle(isDir, selected),
        onClick: () => this.toggleSel(side, f.name),
        onDouble: isDir ? () => navTo(side, joinPath(base, f.name)) : null,
        // Drag the whole selection if this row is part of it, else just this row.
        onDragStart: (e) => {
          const sel = selOf(side);
          const names = sel.includes(f.name) ? sel : [f.name];
          const list = side === 'local' ? s.localFiles : s.remoteFiles;
          const items = list.filter(x => names.includes(x.name)).map(x => ({ name: x.name, kind: x.kind }));
          this._drag = { side, items };
          try {
            e.dataTransfer.effectAllowed = 'copy';
            e.dataTransfer.setData('text/plain', names.join(','));
            if (names.length > 1) {
              // Custom drag image: show the count instead of a single filename.
              const ghost = document.createElement('div');
              ghost.textContent = names.length + ' items';
              ghost.style.cssText = 'position:absolute;top:-1000px;left:-1000px;padding:6px 12px;background:#ff7a59;color:#0c0b0a;font:600 12px/1 "JetBrains Mono",ui-monospace,monospace;border-radius:8px;white-space:nowrap;';
              document.body.appendChild(ghost);
              e.dataTransfer.setDragImage(ghost, 12, 12);
              setTimeout(() => ghost.remove(), 0);
            }
          } catch (_) {}
        },
      };
    };
    const upEntry = (side) => ({
      name: '..', isDir: true, isUp: true, selected: false,
      glyph: '↰', glyphColor: '#8b8b95', sub: 'up',
      rowStyle: { display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 8px', borderRadius: '5px', cursor: 'pointer', fontSize: '11.5px', color: '#8b8b95' },
      onClick: () => navTo(side, parentPath(side === 'local' ? s.localPath : s.remotePath)),
      onDouble: null, onDragStart: () => {},
    });

    // connecting
    let connecting = null;
    if (s.connecting) {
      const h = s.connecting.host;
      const labels = ['Resolving ' + h.addr, 'Negotiating ciphers · aes256-gcm', 'Authenticating · publickey', 'Opening shell session'];
      const failed = s.connecting.failed;
      connecting = {
        titleText: failed ? 'Connection failed' : 'Connecting to ' + h.name,
        target: h.user + '@' + h.addr,
        ringStyle: { position:'absolute', width:'30px', height:'30px', borderRadius:'50%', border:'1.5px solid ' + (failed ? 'rgba(255,107,120,.5)' : 'rgba(255,122,89,.5)'), animation:'acaPulse 1.6s ease-out infinite' },
        ring2Style: { position:'absolute', width:'30px', height:'30px', borderRadius:'50%', border:'1.5px solid ' + (failed ? 'rgba(255,107,120,.5)' : 'rgba(255,122,89,.5)'), animation:'acaPulse 1.6s ease-out infinite', animationDelay:'.8s' },
        spinnerStyle: { width:'46px', height:'46px', borderRadius:'50%', border:'2px solid #1f1f27', borderTopColor: failed ? '#ff6b78' : '#ff7a59', animation: failed ? 'none' : 'acaSpin .9s linear infinite' },
        coreStyle: { position:'absolute', width:'12px', height:'12px', background: failed ? '#ff6b78' : '#ff7a59', borderRadius:'3px', transform:'rotate(45deg)' },
        steps: labels.map((l, i) => {
          let st = 'pending';
          if (i < s.connecting.step) st = 'done';
          else if (i === s.connecting.step) st = failed ? 'error' : 'active';
          const glyph = st === 'done' ? '✓' : st === 'error' ? '✕' : '○';
          const glyphColor = st === 'done' ? '#46d9a0' : st === 'error' ? '#ff6b78' : '#3a3a44';
          const labelColor = st === 'done' ? '#8b8b95' : st === 'active' ? '#ededf0' : st === 'error' ? '#ff6b78' : '#54545e';
          return { label: l, active: st === 'active', notActive: st !== 'active', glyph, glyphColor, labelColor };
        })
      };
    }

    // transfer
    const transfer = s.transfer ? {
      name: s.transfer.name,
      arrow: s.transfer.dir === 'up' ? '↑' : '↓',
      queued: s.queue.length,
      pctLabel: Math.round(s.transfer.pct) + '%',
      fillStyle: { height:'100%', width: s.transfer.pct + '%', background:'linear-gradient(90deg,#ff7a59,#ffb38a)', borderRadius:'4px', transition:'width .12s linear' }
    } : null;

    // toasts
    const tColor = (t) => ({ ok:'#46d9a0', err:'#ff6b78', info:'#6ea8ff' }[t] || '#6ea8ff');
    const tIcon = (t) => ({ ok:'✓', err:'✕', info:'i' }[t] || 'i');
    const toasts = s.toasts.map(t => {
      const c = tColor(t.type);
      return {
        title: t.title, msg: t.msg, icon: tIcon(t.type),
        style: { display:'flex', gap:'11px', alignItems:'flex-start', minWidth:'250px', maxWidth:'340px', padding:'12px 14px', background:'#0e0e13', border:'1px solid #23232c', borderLeft:'3px solid ' + c, borderRadius:'9px', boxShadow:'0 16px 44px rgba(0,0,0,.55)', animation:'acaToast .24s cubic-bezier(.2,.8,.2,1)' },
        iconStyle: { width:'18px', height:'18px', borderRadius:'50%', flex:'none', display:'flex', alignItems:'center', justifyContent:'center', fontSize:'11px', fontWeight:'700', color:'#0a0a0b', background:c, marginTop:'1px' }
      };
    });

    const dragBox = (sideKey) => ({ flex:1, minWidth:0, display:'flex', flexDirection:'column', background: s.dragOver === sideKey ? 'rgba(255,122,89,.06)' : 'transparent', border:'1px dashed ' + (s.dragOver === sideKey ? 'rgba(255,122,89,.55)' : '#1c1c24'), borderRadius:'8px', overflow:'hidden', transition:'all .12s ease' });

    // ---------- DASHBOARD ----------
    const folderNames = [];
    s.hosts.forEach(h => { if (!folderNames.includes(h.folder)) folderNames.push(h.folder); });
    const folderItemStyle = (on) => ({ display:'flex', alignItems:'center', gap:'9px', padding:'7px 9px', borderRadius:'6px', cursor:'pointer', fontSize:'12px', color: on ? '#ededf0' : '#9a9aa3', background: on ? '#15151b' : 'transparent', border:'1px solid ' + (on ? '#26262e' : 'transparent') });
    const allActive = s.activeFolder === 'all';
    const allFolder = { count: s.hosts.length, active: allActive, style: folderItemStyle(allActive), onSelect: () => this.setFolder('all') };
    const folderColorOf = (name) => { const m = s.folderMeta[name]; return (m && m.color) || '#ff7a59'; };
    const folders = folderNames.map(name => {
      const on = s.activeFolder === name;
      const meta = s.folderMeta[name] || {};
      const color = folderColorOf(name);
      return {
        name, count: s.hosts.filter(h => h.folder === name).length, active: on, favorite: !!meta.favorite, color,
        style: folderItemStyle(on), countColor: on ? color : '#54545e',
        onSelect: () => this.setFolder(name), onToggleFav: () => this.toggleFolderFav(name), onEdit: () => this.openFolderEdit(name),
      };
    });
    folders.sort((a, b) => (b.favorite ? 1 : 0) - (a.favorite ? 1 : 0));

    const tagSet = [];
    s.hosts.forEach(h => h.tags.forEach(t => { if (!tagSet.includes(t)) tagSet.push(t); }));
    const tagChipStyle = (on) => ({ padding:'5px 11px', borderRadius:'20px', cursor:'pointer', fontSize:'11px', color: on ? '#ff7a59' : '#9a9aa3', background: on ? 'rgba(255,122,89,.1)' : '#101015', border:'1px solid ' + (on ? 'rgba(255,122,89,.45)' : '#20202a') });
    const allTags = tagSet.map(t => { const on = s.activeTags.includes(t); return { name: t, active: on, style: tagChipStyle(on), onToggle: () => this.toggleTag(t) }; });

    const dq = s.search.trim().toLowerCase();
    const matchHost = (h) => {
      if (s.activeFolder !== 'all' && h.folder !== s.activeFolder) return false;
      if (s.activeTags.length && !s.activeTags.some(t => h.tags.includes(t))) return false;
      if (dq) { const hay = (h.name + ' ' + h.user + ' ' + h.addr + ' ' + h.folder + ' ' + h.tags.join(' ')).toLowerCase(); if (!hay.includes(dq)) return false; }
      return true;
    };
    const filtered = s.hosts.filter(matchHost);
    const authIconOf = (a) => a === 'key' ? '⚿' : a === 'agent' ? '◈' : '•••';
    const authLabelOf = (a) => a === 'key' ? 'key' : a === 'agent' ? 'agent' : 'password';
    const mkCard = (h) => {
      const isNew = s.newHostId === h.id;
      return {
        id: h.id, name: h.name, target: h.user + '@' + h.addr, port: h.port, folder: h.folder, lastUsed: h.lastUsed,
        authIcon: authIconOf(h.auth), authLabel: authLabelOf(h.auth),
        tags: h.tags.map(t => ({ name: t })),
        dotStyle: { width:'8px', height:'8px', borderRadius:'50%', flex:'none', background: h.online ? '#46d9a0' : '#3a3a44', boxShadow: h.online ? '0 0 7px rgba(70,217,160,.6)' : 'none' },
        cardStyle: { display:'flex', flexDirection:'column', gap:'10px', padding:'15px', background: isNew ? '#15130f' : '#0d0d11', border:'1px solid ' + (isNew ? 'rgba(255,122,89,.55)' : '#1c1c24'), borderRadius:'11px', cursor:'pointer', transition:'border-color .15s ease, transform .15s ease', animation: isNew ? 'acaRise .35s ease' : 'none' },
        onConnect: () => this.connectHost(h),
        onEdit: (e) => { e.stopPropagation(); this.openEditHost(h); },
        onCopy: (e) => { e.stopPropagation(); this.copyCommand(h); },
        favorite: !!h.favorite,
        onToggleFav: (e) => { e.stopPropagation(); this.toggleHostFav(h.id); },
      };
    };
    // Favourite connections float into a group at the top; the rest group by folder.
    const favHosts = filtered.filter(h => h.favorite);
    const restHosts = filtered.filter(h => !h.favorite);
    const groupNames = [];
    restHosts.forEach(h => { if (!groupNames.includes(h.folder)) groupNames.push(h.folder); });
    const folderGroups = groupNames.map(name => ({ folder: name, color: folderColorOf(name), count: restHosts.filter(h => h.folder === name).length, cards: restHosts.filter(h => h.folder === name).map(mkCard) }));
    const groups = favHosts.length
      ? [{ folder: '★ Favorites', color: '#ffcf5c', count: favHosts.length, cards: favHosts.map(mkCard) }, ...folderGroups]
      : folderGroups;

    // ---------- ADD HOST FORM ----------
    const f = s.form;
    const segStyle = (on) => ({ flex:1, textAlign:'center', padding:'9px', borderRadius:'7px', cursor:'pointer', fontSize:'12px', color: on ? '#0c0b0a' : '#b9b9c2', background: on ? '#ff7a59' : '#101015', border:'1px solid ' + (on ? '#ff7a59' : '#20202a'), fontWeight: on ? '600' : '400', transition:'all .12s ease' });
    const subSegStyle = (on) => ({ flex:1, textAlign:'center', padding:'7px', borderRadius:'6px', cursor:'pointer', fontSize:'11.5px', color: on ? '#ededf0' : '#8b8b95', background: on ? '#1a1a20' : 'transparent', border:'1px solid ' + (on ? '#2c2c36' : 'transparent') });
    const keyVal = this.validateKey(f.keyText);
    const keyStateColor = keyVal.state === 'valid' ? '#46d9a0' : keyVal.state === 'error' ? '#ff6b78' : '#6a6a74';
    const keyStateIcon = keyVal.state === 'valid' ? '✓' : keyVal.state === 'error' ? '✕' : '○';
    const keyBlocks = f.auth === 'key' && f.keyMode === 'text' && f.keyText.trim() && keyVal.state === 'error';
    const canSaveHost = !!(f.name.trim() && f.host.trim()) && !keyBlocks;

    // ---------- SETTINGS ----------
    const st = s.settings;
    const toggleTrackStyle = (on) => ({ width:'38px', height:'22px', borderRadius:'11px', background: on ? '#ff7a59' : '#26262e', position:'relative', cursor:'pointer', transition:'background .15s ease', flex:'none' });
    const toggleKnobStyle = (on) => ({ position:'absolute', top:'2px', left: on ? '18px' : '2px', width:'18px', height:'18px', borderRadius:'50%', background:'#fff', transition:'left .15s ease' });
    const themeOptions = Object.keys(this.THEMES).map(id => { const th = this.THEMES[id]; const on = id === s.themeId; return { id, name: th.name, active: on, dotStyle: { width:'12px', height:'12px', borderRadius:'4px', background: th.accent, flex:'none' }, style: { display:'flex', alignItems:'center', gap:'8px', padding:'8px 10px', borderRadius:'7px', cursor:'pointer', fontSize:'12px', color: on ? '#ededf0' : '#9a9aa3', background: on ? '#15151b' : '#0e0e12', border:'1px solid ' + (on ? 'rgba(255,122,89,.4)' : '#1c1c24') }, onPick: () => { this.setState({ themeId: id }); } }; });

    return {
      sidebarOpen: s.sidebarOpen, sftpOpen: s.sftpOpen, paletteOpen: s.paletteOpen, themesOpen: s.themesOpen,
      paletteQuery: s.paletteQuery, paletteRef: this.paletteRef, paletteItems,
      tabs, panes, tabPanes, paneWrapRef: this.paneWrap,
      paneWrapStyle: { flex:1, minWidth:0, minHeight:0, display:'flex', flexDirection: layout === 'row' ? 'row' : 'column', gap:'8px' },
      themesList, themesCount: Object.keys(this.THEMES).length,
      localFiles: [upEntry('local'), ...s.localFiles.map(f => mkFile(f, 'local'))],
      remoteFiles: [upEntry('remote'), ...s.remoteFiles.map(f => mkFile(f, 'remote'))],
      localColStyle: dragBox('local'), remoteColStyle: dragBox('remote'),
      localPath: s.localPath || '~', remotePath: s.remotePath || '/', sftpHost: activeTab ? activeTab.title : '',
      sftpReady: s.sftpStatus === 'ready', sftpMsg: s.sftpErr || (s.sftpStatus === 'connecting' ? 'Connecting…' : 'Not connected'),
      transferActive: !!transfer, transfer,
      conflictOpen: !!s.conflict,
      conflictName: s.conflict ? s.conflict.file.name : '',
      conflictDest: s.conflict ? (s.conflict.dir === 'up' ? s.remotePath : s.localPath) : '',
      conflictAll: s.conflictAll,
      toggleConflictAll: () => this.setState(st => ({ conflictAll: !st.conflictAll })),
      conflictReplace: () => this.resolveConflict('replace'),
      conflictSkip: () => this.resolveConflict('skip'),
      connectingActive: !!connecting, connecting,
      connectingCardStyle: { width:'420px', maxWidth:'90%', background:'#0c0c10', border:'1px solid #26262e', borderRadius:'15px', padding:'28px', boxShadow:'0 36px 90px rgba(0,0,0,.65)', animation: (s.connecting && s.connecting.failed) ? 'acaShake .5s ease' : 'acaModal .18s cubic-bezier(.2,.8,.2,1)' },
      toasts,
      statusTheme: theme.name, statusHost: activeTab ? (activeTab.user + '@' + activeTab.addr) : '',
      onDragOver: (e) => { e.preventDefault(); try { e.dataTransfer.dropEffect = 'copy'; } catch (_) {} },
      onDropRemote: (e) => { e.preventDefault(); this.sftpDrop('remote'); },
      onDropLocal: (e) => { e.preventDefault(); this.sftpDrop('local'); },
      onDragEnterRemote: () => this.setState({ dragOver: 'remote' }),
      onDragEnterLocal: () => this.setState({ dragOver: 'local' }),
      onDragLeave: () => {},
      toggleSidebar: () => this.setState(st => ({ sidebarOpen: !st.sidebarOpen })),
      winMin: () => this.winAction('min'), winMax: () => this.winAction('max'), winClose: () => this.winAction('close'),
      toggleSftp: () => this.toggleSftp(),
      openPalette: () => this.setState({ paletteOpen: true, paletteQuery: '' }),
      closePalette: () => this.setState({ paletteOpen: false }),
      setPaletteQuery: (e) => this.setState({ paletteQuery: e.target.value }),
      openThemes: () => this.setState({ themesOpen: true }),
      closeThemes: () => this.setState({ themesOpen: false }),
      aboutOpen: s.aboutOpen,
      openAbout: () => this.setState({ aboutOpen: true }),
      closeAbout: () => this.setState({ aboutOpen: false }),
      author: AUTHOR, openExt,
      newTab: () => this.newTab(),
      splitRight: this.splitRight, splitDown: this.splitDown,
      cancelConnect: this.cancelConnect,
      secretPromptOpen: !!s.secretPrompt,
      secretPromptTitle: s.secretPrompt ? ('Connect to ' + s.secretPrompt.host.name) : '',
      secretPromptLabel: s.secretPrompt && s.secretPrompt.kind === 'key' ? 'Key passphrase' : 'Password',
      secretPromptHint: s.secretPrompt && s.secretPrompt.kind === 'key' ? 'Blank if your key has no passphrase. Never written to disk.' : 'Used for this connection only. Never written to disk.',
      secretValue: s.secretPrompt ? s.secretPrompt.value : '',
      onSecretInput: (e) => this.setState(st => ({ secretPrompt: st.secretPrompt ? { ...st.secretPrompt, value: e.target.value } : null })),
      onSecretKey: (e) => { if (e.key === 'Enter') { e.preventDefault(); this.submitSecret(); } },
      submitSecret: () => this.submitSecret(), cancelSecret: () => this.cancelSecret(),
      hostKeyOpen: !!s.hostKeyPrompt,
      hostKeyName: s.hostKeyPrompt ? s.hostKeyPrompt.host.name : '',
      hostKeyTarget: s.hostKeyPrompt ? (s.hostKeyPrompt.host.user + '@' + s.hostKeyPrompt.host.addr + ':' + (s.hostKeyPrompt.host.port || '22')) : '',
      hostKeyFp: s.hostKeyPrompt ? s.hostKeyPrompt.fp : '',
      acceptHostKey: this.acceptHostKey, rejectHostKey: this.rejectHostKey,
      confirmCloseOpen: !!s.confirmClose,
      confirmCloseName: s.confirmClose ? s.confirmClose.name : '',
      confirmCloseTab: () => this.confirmCloseTab(),
      cancelConfirmClose: () => this.setState({ confirmClose: null }),

      // view nav
      isDashboard: s.view === 'dashboard', isWorkspace: s.view === 'workspace',
      sessionCount: s.tabs.length,
      navDashStyle: folderItemStyle(s.view === 'dashboard'),
      navTermStyle: folderItemStyle(s.view === 'workspace'),
      goDashboard: () => this.setView('dashboard'),
      goTerminal: () => this.setView('workspace'),

      // dashboard
      allFolder, folders, allTags, groups,
      totalHosts: s.hosts.length, filteredCount: filtered.length, dashEmpty: filtered.length === 0,
      hasTags: tagSet.length > 0,
      searchValue: s.search, onSearch: (e) => this.setSearch(e.target.value), clearSearch: () => this.setSearch(''),
      activeFolderLabel: s.activeFolder === 'all' ? 'All connections' : s.activeFolder,
      folderEditOpen: !!s.folderEdit,
      folderEditName: s.folderEdit ? s.folderEdit.newName : '',
      folderEditColor: s.folderEdit ? s.folderEdit.color : '',
      folderEditFav: s.folderEdit ? !!s.folderEdit.favorite : false,
      onFolderEditName: (e) => this.setFolderEdit('newName', e.target.value),
      pickFolderColor: (c) => this.setFolderEdit('color', c),
      toggleFolderEditFav: () => this.setFolderEdit('favorite', !(this.state.folderEdit && this.state.folderEdit.favorite)),
      saveFolderEdit: () => this.saveFolderEdit(),
      cancelFolderEdit: () => this.setState({ folderEdit: null }),
      folderPalette: ['#ff7a59', '#ffcf5c', '#46d9a0', '#6ea8ff', '#bd93f9', '#ff6b78', '#f5c2e7', '#88c0d0'],

      // add host
      addHostOpen: s.addHostOpen, openAddHost: () => this.openAddHost(), closeAddHost: () => this.closeAddHost(),
      isEditing: !!s.editingId,
      modalTitle: s.editingId ? 'Edit connection' : 'New connection',
      modalSubtitle: s.editingId ? 'Changes are saved locally to this device' : 'Saved locally — credentials never leave this device',
      saveLabel: s.editingId ? 'Save changes' : 'Create host',
      deleteHost: () => this.deleteHost(s.editingId),
      fName: f.name, fHost: f.host, fPort: f.port, fUser: f.user,
      fPassword: f.password, fKeyPath: f.keyPath, fKeyText: f.keyText, fPassphrase: f.passphrase, fFolder: f.folder, fTagInput: f.tagInput,
      fTags: f.tags.map(t => ({ name: t, onRemove: () => this.removeTag(t) })),
      authIsPassword: f.auth === 'password', authIsKey: f.auth === 'key', authIsAgent: f.auth === 'agent',
      authPwStyle: segStyle(f.auth === 'password'), authKeyStyle: segStyle(f.auth === 'key'), authAgentStyle: segStyle(f.auth === 'agent'),
      setAuthPassword: () => this.setField('auth', 'password'), setAuthKey: () => this.setField('auth', 'key'), setAuthAgent: () => this.setField('auth', 'agent'),
      keyModeFile: f.keyMode === 'file', keyModeText: f.keyMode === 'text',
      keyFileStyle: subSegStyle(f.keyMode === 'file'), keyTextStyle: subSegStyle(f.keyMode === 'text'),
      setKeyModeFile: () => this.setField('keyMode', 'file'), setKeyModeText: () => this.setField('keyMode', 'text'),
      onFKeyText: (e) => this.setField('keyText', e.target.value),
      keyShowStatus: f.keyText.trim().length > 0,
      keyStatusIcon: keyStateIcon, keyStatusMsg: keyVal.message,
      keyStatusStyle: { display:'flex', alignItems:'center', gap:'7px', marginTop:'8px', fontSize:'11px', color: keyStateColor },
      keyIconStyle: { width:'15px', height:'15px', borderRadius:'50%', flex:'none', display:'flex', alignItems:'center', justifyContent:'center', fontSize:'9px', fontWeight:'700', color:'#0a0a0b', background: keyStateColor },
      keyTextAreaStyle: { width:'100%', minHeight:'108px', resize:'vertical', background:'#0e0e12', border:'1px solid ' + (keyVal.state === 'error' && f.keyText.trim() ? 'rgba(255,107,120,.5)' : keyVal.state === 'valid' ? 'rgba(70,217,160,.4)' : '#20202a'), borderRadius:'8px', padding:'11px 13px', color:'#ededf0', font:'inherit', fontSize:'11.5px', lineHeight:'1.5', outline:'none' },
      onFName: (e) => this.setField('name', e.target.value),
      onFHost: (e) => this.setField('host', e.target.value),
      onFPort: (e) => this.setField('port', e.target.value),
      onFUser: (e) => this.setField('user', e.target.value),
      onFPassword: (e) => this.setField('password', e.target.value),
      onFKeyPath: (e) => this.setField('keyPath', e.target.value),
      onFPassphrase: (e) => this.setField('passphrase', e.target.value),
      onFFolder: (e) => this.setField('folder', e.target.value),
      onFTagInput: (e) => this.setField('tagInput', e.target.value),
      onFTagKey: (e) => { if (e.key === 'Enter') { e.preventDefault(); this.addTagFromInput(); } },
      onBrowseKey: () => this.setField('keyPath', '~/.ssh/id_ed25519'),
      folderChips: folderNames.map(name => ({ name, onPick: () => this.setField('folder', name) })),
      saveHost: () => this.saveHost(), canSaveHost,
      saveHostStyle: { padding:'10px 20px', borderRadius:'8px', border:'none', font:'inherit', fontSize:'12.5px', fontWeight:'600', cursor: canSaveHost ? 'pointer' : 'not-allowed', color:'#0c0b0a', background: canSaveHost ? '#ff7a59' : '#3a3024', opacity: canSaveHost ? '1' : '.55' },

      // settings
      settingsOpen: s.settingsOpen, openSettings: () => this.openSettings(), closeSettings: () => this.closeSettings(),
      themeOptions,
      fontSize: st.fontSize, fontSizeLabel: st.fontSize + 'px', onFontSize: (e) => this.setSetting('fontSize', parseInt(e.target.value, 10)),
      cursorBlockStyle: segStyle(st.cursor === 'block'), cursorBarStyle: segStyle(st.cursor === 'bar'), cursorUnderStyle: segStyle(st.cursor === 'underline'),
      setCursorBlock: () => this.setSetting('cursor', 'block'), setCursorBar: () => this.setSetting('cursor', 'bar'), setCursorUnder: () => this.setSetting('cursor', 'underline'),
      scrollback: st.scrollback, onScrollback: (e) => this.setSetting('scrollback', e.target.value),
      confirmCloseTrack: toggleTrackStyle(st.confirmClose), confirmCloseKnob: toggleKnobStyle(st.confirmClose), toggleConfirmClose: () => this.setSetting('confirmClose', !st.confirmClose),
      restoreTabsTrack: toggleTrackStyle(st.restoreTabs), restoreTabsKnob: toggleKnobStyle(st.restoreTabs), toggleRestoreTabs: () => this.setSetting('restoreTabs', !st.restoreTabs),
      lockIdleTrack: toggleTrackStyle(st.lockIdle), lockIdleKnob: toggleKnobStyle(st.lockIdle),
      toggleLockIdle: () => { const c = this.state.settings; if (!c.lockIdle) { if (c.lockHash) this.setSetting('lockIdle', true); else this.setState({ lockPrompt: { mode: 'set', value: '' } }); } else this.setSetting('lockIdle', false); },
      locked: s.locked, unlockValue: s.unlockValue,
      onUnlockInput: (e) => this.setState({ unlockValue: e.target.value }),
      onUnlockKey: (e) => { if (e.key === 'Enter') { e.preventDefault(); this.tryUnlock(this.state.unlockValue); } },
      submitUnlock: () => this.tryUnlock(this.state.unlockValue),
      lockSetOpen: !!(s.lockPrompt && s.lockPrompt.mode === 'set'),
      lockSetValue: s.lockPrompt ? s.lockPrompt.value : '',
      onLockSetInput: (e) => this.setState(st0 => ({ lockPrompt: st0.lockPrompt ? { ...st0.lockPrompt, value: e.target.value } : null })),
      onLockSetKey: (e) => { if (e.key === 'Enter') { e.preventDefault(); this.hashAndSetLock(this.state.lockPrompt ? this.state.lockPrompt.value : ''); } },
      submitLockSet: () => this.hashAndSetLock(this.state.lockPrompt ? this.state.lockPrompt.value : ''),
      cancelLockSet: () => this.setState({ lockPrompt: null }),
      fwdOpen: !!s.fwdPrompt,
      fwdLocal: s.fwdPrompt ? s.fwdPrompt.localPort : '',
      fwdRemoteHost: s.fwdPrompt ? s.fwdPrompt.remoteHost : '',
      fwdRemotePort: s.fwdPrompt ? s.fwdPrompt.remotePort : '',
      onFwdLocal: (e) => this.setFwd('localPort', e.target.value),
      onFwdRemoteHost: (e) => this.setFwd('remoteHost', e.target.value),
      onFwdRemotePort: (e) => this.setFwd('remotePort', e.target.value),
      submitForward: () => this.submitForward(),
      cancelForward: () => this.setState({ fwdPrompt: null }),
      forwardCount: s.forwards.length,
      mcpOpen: s.mcpOpen, mcpRunning: s.mcpRunning, mcpUrl: MCP_URL, mcpToken: s.settings.mcpToken || '',
      mcpLog: s.mcpLog, mcpExposedCount: s.hosts.filter(h => h.agentAllowed).length,
      mcpHosts: s.hosts.map(h => ({ id: h.id, name: h.name, target: h.user + '@' + h.addr, allowed: !!h.agentAllowed, onToggle: () => this.toggleHostAgent(h.id) })),
      mcpConfig: JSON.stringify({ mcpServers: { sshache: { url: MCP_URL, headers: { Authorization: 'Bearer ' + (s.settings.mcpToken || '<token>') } } } }, null, 2),
      openMcp: () => this.openMcp(), closeMcp: () => this.setState({ mcpOpen: false }), toggleMcp: () => this.toggleMcp(),
      copyMcp: (text) => { try { navigator.clipboard.writeText(text).then(() => this.pushToast({ type: 'ok', title: 'Copied', msg: '' })).catch(() => {}); } catch (e) {} },
      approvalOpen: !!s.approvalReq,
      approvalHost: s.approvalReq ? s.approvalReq.host : '',
      approvalCommand: s.approvalReq ? s.approvalReq.command : '',
      approve: () => this.mcpRespond(true), deny: () => this.mcpRespond(false),
      onExport: () => this.exportConfig(),
      onImport: () => this.importConfig(),
      ioOpen: !!s.ioPrompt,
      ioTitle: s.ioPrompt ? (s.ioPrompt.mode === 'export' ? 'Export — encrypt with a password' : 'Import — enter the password') : '',
      ioLabel: s.ioPrompt ? (s.ioPrompt.mode === 'export' ? 'New password' : 'Password') : '',
      ioHint: s.ioPrompt ? (s.ioPrompt.mode === 'export' ? 'The backup (hosts + saved secrets) is encrypted with this password — you’ll need it to import.' : 'Enter the password used when this file was exported.') : '',
      ioCta: s.ioPrompt ? (s.ioPrompt.mode === 'export' ? 'Choose file & export' : 'Import') : '',
      ioValue: s.ioPrompt ? s.ioPrompt.value : '',
      onIoInput: (e) => this.setState(st => ({ ioPrompt: st.ioPrompt ? { ...st.ioPrompt, value: e.target.value } : null })),
      onIoKey: (e) => { if (e.key === 'Enter') { e.preventDefault(); this.ioSubmit(); } },
      ioSubmit: () => this.ioSubmit(), ioCancel: () => this.ioCancel(),

      stop: (e) => e.stopPropagation()
    };
  }

  render() {
    const v = this.renderVals();
    return (
      <div style={css("position:relative;height:100vh;width:100%;display:flex;flex-direction:column;background:#09090b;color:#ededf0;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:13px;overflow:hidden;")}>

        {/* TITLE BAR */}
        <div data-tauri-drag-region style={css("height:42px;flex:none;display:flex;align-items:center;gap:12px;padding:0 12px;background:#0a0a0d;border-bottom:1px solid #16161c;")}>
          <div style={css("display:flex;align-items:center;gap:9px;")}>
            <img src={logoMark} width="20" height="20" alt="SSH Ache" style={{ borderRadius: "6px", boxShadow: "0 0 12px rgba(255,77,112,.45)" }} />
            <span style={css("font-weight:700;font-size:13px;letter-spacing:.01em;color:#f2f2f5;")}>SSH&nbsp;Ache</span>
            <span style={css("font-size:10px;color:#6a6a74;border:1px solid #26262e;border-radius:4px;padding:1px 5px;")}>v0.4.0</span>
          </div>
          <span data-tauri-drag-region style={css("flex:1;")}></span>
          <div style={css("display:flex;align-items:center;gap:7px;")}>
            <Hov onClick={v.openPalette} s="display:flex;align-items:center;gap:7px;padding:5px 9px;background:#101015;border:1px solid #20202a;border-radius:6px;cursor:pointer;color:#9a9aa3;font-size:11px;" h="background:#15151b;color:#ededf0;">
              <span>Search &amp; commands</span><span style={css("border:1px solid #2c2c36;border-radius:3px;padding:0 4px;color:#6a6a74;")}>⌘K</span>
            </Hov>
            <Hov onClick={v.openThemes} title="Themes" s="display:flex;align-items:center;gap:4px;padding:6px 9px;background:#101015;border:1px solid #20202a;border-radius:6px;cursor:pointer;" h="background:#15151b;">
              <span style={css("width:9px;height:9px;border-radius:50%;background:#ff7a59;")}></span>
              <span style={css("width:9px;height:9px;border-radius:50%;background:#6ea8ff;margin-left:-4px;")}></span>
              <span style={css("width:9px;height:9px;border-radius:50%;background:#46d9a0;margin-left:-4px;")}></span>
            </Hov>
            <Hov onClick={v.toggleSftp} title="SFTP" s="padding:6px 10px;background:#101015;border:1px solid #20202a;border-radius:6px;cursor:pointer;color:#b9b9c2;font-size:11px;" h="background:#15151b;color:#ededf0;">⇅&nbsp;SFTP</Hov>
            <Hov onClick={v.openAbout} title="About · support the author" s="width:32px;height:28px;display:flex;align-items:center;justify-content:center;background:#101015;border:1px solid #20202a;border-radius:6px;cursor:pointer;" h="background:#15151b;border-color:rgba(255,95,109,.4);">
              <svg width="15" height="15" viewBox="0 0 24 24" className="aca-heart" aria-hidden="true">
                <defs><linearGradient id="acaHeartGrad" x1="2" y1="3" x2="22" y2="21" gradientUnits="userSpaceOnUse"><stop stopColor="#ff8a63"/><stop offset="1" stopColor="#ff3d7f"/></linearGradient></defs>
                <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" fill="url(#acaHeartGrad)"/>
              </svg>
            </Hov>
          </div>
          <div style={css("display:flex;gap:3px;margin-left:4px;align-items:center;")}>
            <Hov onClick={v.winMin} title="Minimize" s="width:26px;height:22px;display:flex;align-items:center;justify-content:center;border-radius:5px;cursor:pointer;" h="background:#15151b;">
              <span style={css("width:11px;height:1.5px;background:#8b8b95;")}></span>
            </Hov>
            <Hov onClick={v.winMax} title="Maximize" s="width:26px;height:22px;display:flex;align-items:center;justify-content:center;border-radius:5px;cursor:pointer;" h="background:#15151b;">
              <span style={css("width:9px;height:9px;border:1.5px solid #8b8b95;border-radius:2px;")}></span>
            </Hov>
            <Hov onClick={v.winClose} title="Close" s="width:26px;height:22px;display:flex;align-items:center;justify-content:center;border-radius:5px;cursor:pointer;" h="background:rgba(244,88,78,.9);">
              <span style={css("position:relative;width:11px;height:11px;")}>
                <span style={css("position:absolute;top:5px;left:0;width:11px;height:1.5px;background:#cfcfd6;transform:rotate(45deg);")}></span>
                <span style={css("position:absolute;top:5px;left:0;width:11px;height:1.5px;background:#cfcfd6;transform:rotate(-45deg);")}></span>
              </span>
            </Hov>
          </div>
        </div>

        {/* BODY */}
        <div style={css("flex:1;min-height:0;display:flex;")}>

          {/* SIDEBAR */}
          {v.sidebarOpen && (
            <div style={css("width:224px;flex:none;background:#0a0a0d;border-right:1px solid #16161c;display:flex;flex-direction:column;")}>
              <div style={css("padding:11px 10px 4px;display:flex;flex-direction:column;gap:3px;")}>
                <div onClick={v.goDashboard} style={v.navDashStyle}>
                  <span style={css("font-size:13px;flex:none;width:16px;text-align:center;")}>⊞</span>
                  <span style={css("flex:1;")}>Dashboard</span>
                </div>
                <div onClick={v.goTerminal} style={v.navTermStyle}>
                  <span style={css("font-size:12px;flex:none;width:16px;text-align:center;color:#ff7a59;")}>›_</span>
                  <span style={css("flex:1;")}>Terminal</span>
                  <span style={css("font-size:9.5px;color:#54545e;border:1px solid #20202a;border-radius:9px;padding:1px 6px;")}>{v.sessionCount}</span>
                </div>
              </div>
              <div style={css("flex:1;overflow:auto;padding:6px 10px 8px;")}>
                <div style={css("font-size:9px;letter-spacing:.14em;color:#46464f;text-transform:uppercase;padding:11px 8px 6px;")}>Folders</div>
                <div onClick={v.allFolder.onSelect} style={v.allFolder.style}>
                  <span style={css("font-size:11px;flex:none;width:16px;text-align:center;color:#6a6a74;")}>≡</span>
                  <span style={css("flex:1;")}>All connections</span>
                  <span style={css("font-size:10px;color:#54545e;")}>{v.allFolder.count}</span>
                </div>
                {v.folders.map((folder) => (
                  <FolderRow key={folder.name} folder={folder} />
                ))}
              </div>
              <div style={css("padding:10px;border-top:1px solid #14141a;display:flex;flex-direction:column;gap:7px;")}>
                <Hov as="button" onClick={v.openAddHost} s="display:flex;align-items:center;justify-content:center;gap:7px;padding:9px;background:#ff7a59;border:none;border-radius:7px;color:#0c0b0a;font:inherit;font-size:12px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">
                  <span style={css("font-size:14px;")}>+</span><span>Add host</span>
                </Hov>
                <div style={css("display:flex;align-items:center;gap:8px;padding:4px 2px;font-size:10px;color:#54545e;")}>
                  <span style={css("width:6px;height:6px;border-radius:50%;background:#46d9a0;box-shadow:0 0 6px rgba(70,217,160,.6);")}></span>
                  <span>encrypted at rest</span>
                </div>
                <div style={css("display:flex;gap:7px;")}>
                  <Hov as="button" onClick={v.openThemes} s="flex:1;padding:7px 8px;background:#101015;border:1px solid #20202a;border-radius:6px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Themes</Hov>
                  <Hov as="button" onClick={v.openSettings} s="flex:1;padding:7px 8px;background:#101015;border:1px solid #20202a;border-radius:6px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Settings</Hov>
                </div>
              </div>
            </div>
          )}

          {/* MAIN */}
          <div style={css("flex:1;min-width:0;display:flex;flex-direction:column;")}>

            {/* DASHBOARD */}
            {v.isDashboard && (
              <div style={css("flex:1;min-height:0;display:flex;flex-direction:column;overflow:hidden;")}>
                <div style={css("flex:none;padding:22px 26px 14px;display:flex;align-items:flex-end;gap:14px;")}>
                  <div>
                    <div style={css("font-size:20px;font-weight:700;color:#f2f2f5;letter-spacing:-.01em;")}>{v.activeFolderLabel}</div>
                    <div style={css("font-size:11.5px;color:#6a6a74;margin-top:3px;")}>{v.filteredCount} of {v.totalHosts} connections · stored locally</div>
                  </div>
                  <span style={css("flex:1;")}></span>
                  <Hov as="button" onClick={v.openAddHost} s="display:flex;align-items:center;gap:8px;padding:10px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">
                    <span style={css("font-size:15px;")}>+</span><span>New host</span>
                  </Hov>
                </div>
                <div style={css("flex:none;padding:0 26px;")}>
                  <div style={css("display:flex;align-items:center;gap:10px;background:#0d0d11;border:1px solid #20202a;border-radius:9px;padding:11px 14px;")}>
                    <span style={css("color:#54545e;font-size:13px;")}>⌕</span>
                    <input value={v.searchValue} onChange={v.onSearch} placeholder="Search by name, host, folder or tag…" spellCheck={false} style={css("flex:1;background:transparent;border:none;outline:none;color:#ededf0;font:inherit;font-size:13px;")} />
                  </div>
                  {v.hasTags && (
                    <div style={css("display:flex;flex-wrap:wrap;gap:7px;margin-top:13px;")}>
                      {v.allTags.map((tag) => (
                        <div key={tag.name} onClick={tag.onToggle} style={tag.style}>#{tag.name}</div>
                      ))}
                    </div>
                  )}
                </div>
                <div style={css("flex:1;overflow:auto;padding:18px 26px 26px;")}>
                  {v.groups.map((group) => (
                    <div key={group.folder} style={css("margin-bottom:24px;")}>
                      <div style={css("display:flex;align-items:center;gap:8px;margin-bottom:12px;")}>
                        <span style={{ fontSize: '11px', letterSpacing: '.04em', color: group.color, textTransform: 'uppercase' }}>{group.folder}</span>
                        <span style={css("font-size:10px;color:#54545e;border:1px solid #20202a;border-radius:9px;padding:0 6px;")}>{group.count}</span>
                        <span style={css("flex:1;height:1px;background:#15151b;")}></span>
                      </div>
                      <div style={css("display:grid;grid-template-columns:repeat(auto-fill,minmax(248px,1fr));gap:13px;")}>
                        {group.cards.map((card) => (
                          <Hov key={card.id} onClick={card.onConnect} s={card.cardStyle} h="border-color:rgba(255,122,89,.55);transform:translateY(-2px);">
                            <div style={css("display:flex;align-items:center;gap:9px;")}>
                              <span style={card.dotStyle}></span>
                              <span style={css("flex:1;font-size:13.5px;font-weight:600;color:#ededf0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{card.name}</span>
                              <Hov onClick={card.onToggleFav} title="Favorite" s={{ width: '24px', height: '24px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: card.favorite ? '#ffcf5c' : '#6a6a74', border: '1px solid #20202a', borderRadius: '6px', fontSize: '12px', cursor: 'pointer' }} h="background:#16161c;border-color:#2c2c36;">{card.favorite ? '★' : '☆'}</Hov>
                              <Hov onClick={card.onCopy} title="Copy ssh command" s="width:24px;height:24px;display:flex;align-items:center;justify-content:center;color:#6a6a74;border:1px solid #20202a;border-radius:6px;font-size:11px;" h="background:#16161c;color:#ededf0;border-color:#2c2c36;">⧉</Hov>
                              <Hov onClick={card.onEdit} title="Edit connection" s="width:24px;height:24px;display:flex;align-items:center;justify-content:center;color:#6a6a74;border:1px solid #20202a;border-radius:6px;font-size:11px;" h="background:#16161c;color:#ededf0;border-color:#2c2c36;">✎</Hov>
                              <span style={css("font-size:10px;color:#6a6a74;border:1px solid #20202a;border-radius:5px;padding:2px 6px;")}>{card.authIcon} {card.authLabel}</span>
                            </div>
                            <div style={css("font-size:11.5px;color:#9a9aa3;font-family:inherit;")}>{card.target}<span style={css("color:#54545e;")}>:{card.port}</span></div>
                            <div style={css("display:flex;flex-wrap:wrap;gap:5px;")}>
                              {card.tags.map((t, ti) => (
                                <span key={ti} style={css("font-size:10px;color:#8b8b95;background:#15151b;border-radius:5px;padding:2px 7px;")}>#{t.name}</span>
                              ))}
                            </div>
                            <div style={css("display:flex;align-items:center;gap:6px;margin-top:1px;")}>
                              <span style={css("font-size:10px;color:#54545e;")}>last used {card.lastUsed}</span>
                              <span style={css("flex:1;")}></span>
                              <span style={css("font-size:10.5px;color:#ff7a59;font-weight:600;")}>Connect →</span>
                            </div>
                          </Hov>
                        ))}
                      </div>
                    </div>
                  ))}
                  {v.dashEmpty && (
                    <div style={css("display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:70px 20px;text-align:center;")}>
                      <span style={css("width:46px;height:46px;border:1.5px dashed #2a2a33;border-radius:12px;display:flex;align-items:center;justify-content:center;color:#3a3a44;font-size:20px;")}>⌕</span>
                      <div style={css("font-size:13px;color:#9a9aa3;")}>No connections match your filters</div>
                      <div onClick={v.clearSearch} style={css("font-size:11.5px;color:#ff7a59;cursor:pointer;")}>Clear search</div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TERMINAL WORKSPACE */}
            {v.isWorkspace && (
              <div style={css("flex:1;min-height:0;display:flex;flex-direction:column;")}>

                {/* TAB BAR */}
                <div style={css("height:42px;flex:none;display:flex;align-items:center;gap:4px;padding:0 8px;background:#0b0b0e;border-bottom:1px solid #16161c;")}>
                  <Hov onClick={v.toggleSidebar} title="Toggle sidebar (⌘B)" s="width:26px;height:26px;display:flex;align-items:center;justify-content:center;border-radius:5px;color:#6a6a74;cursor:pointer;flex:none;" h="background:#15151b;color:#ededf0;">▤</Hov>
                  <div style={css("display:flex;align-items:center;gap:4px;overflow:hidden;")}>
                    {v.tabs.map((tab) => (
                      <div key={tab.id} onClick={tab.onSelect} style={tab.style}>
                        <span style={tab.dotStyle}></span>
                        <span style={css("overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{tab.title}</span>
                        <Hov onClick={tab.onClose} s="margin-left:2px;width:16px;height:16px;display:flex;align-items:center;justify-content:center;border-radius:4px;color:#54545e;font-size:13px;" h="background:#26262e;color:#ededf0;">×</Hov>
                      </div>
                    ))}
                  </div>
                  <Hov onClick={v.newTab} title="New tab" s="width:26px;height:26px;display:flex;align-items:center;justify-content:center;border-radius:5px;color:#8b8b95;cursor:pointer;flex:none;font-size:15px;" h="background:#15151b;color:#ededf0;">+</Hov>
                  <span style={css("flex:1;")}></span>
                  <div style={css("display:flex;align-items:center;gap:3px;")}>
                    <Hov onClick={v.splitRight} title="Split right (⌘D)" s="width:28px;height:26px;display:flex;align-items:center;justify-content:center;border-radius:5px;color:#8b8b95;cursor:pointer;" h="background:#15151b;color:#ededf0;"><span style={css("display:flex;gap:2px;")}><span style={css("width:5px;height:13px;border:1px solid currentColor;border-radius:2px;")}></span><span style={css("width:5px;height:13px;border:1px solid currentColor;border-radius:2px;")}></span></span></Hov>
                    <Hov onClick={v.splitDown} title="Split down" s="width:28px;height:26px;display:flex;align-items:center;justify-content:center;border-radius:5px;color:#8b8b95;cursor:pointer;" h="background:#15151b;color:#ededf0;"><span style={css("display:flex;flex-direction:column;gap:2px;")}><span style={css("width:13px;height:5px;border:1px solid currentColor;border-radius:2px;")}></span><span style={css("width:13px;height:5px;border:1px solid currentColor;border-radius:2px;")}></span></span></Hov>
                  </div>
                </div>

                {/* WORKSPACE */}
                <div style={css("flex:1;min-height:0;display:flex;padding:10px;")}>
                  {v.tabPanes.map((tp) => (
                  <div key={tp.id} ref={tp.active ? v.paneWrapRef : null} style={tp.wrapStyle}>
                    {tp.panes.map((pane) => (
                      <div key={pane.id} onMouseDown={pane.onActivate} style={pane.boxStyle}>
                        {pane.notFirst && (<div onMouseDown={pane.onGutterDown} style={pane.gutterStyle}></div>)}
                        <div style={pane.headStyle}>
                          <span style={css("width:7px;height:7px;border-radius:2px;transform:rotate(45deg);background:#ff7a59;flex:none;")}></span>
                          <span style={css("font-size:11px;color:#9a9aa3;")}>{pane.hostLabel}</span>
                          <span style={css("flex:1;")}></span>
                          <span style={css("font-size:10px;color:#54545e;letter-spacing:.05em;")}>{pane.cwd}</span>
                          <Hov onMouseDown={pane.onClose} s="width:18px;height:18px;display:flex;align-items:center;justify-content:center;color:#54545e;border-radius:4px;cursor:pointer;" h="background:#222;color:#ededf0;">×</Hov>
                        </div>
                        {pane.live ? (
                          <TermPane key={pane.id + ":t"} session={{ sessionId: pane.sessionId, host: pane.hostObj, secret: pane.secret, keyText: pane.keyText, kind: pane.kind }} theme={pane.termTheme} fontSize={pane.fontSize} cursor={pane.cursor} scrollback={pane.scrollback} onConnected={pane.onConnected} onError={pane.onError} onClosed={pane.onClosed} onHostKey={pane.onHostKey} register={this.registerTerm} />
                        ) : (
                        <div style={pane.termStyle}>
                          {pane.lines.map((line, li) => (
                            <div key={li} style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", color: line.color }}>{line.display}</div>
                          ))}
                          <div style={css("display:flex;align-items:center;white-space:pre;margin-top:3px;")}>
                            <span style={{ color: pane.promptColor, fontWeight: 600 }}>{pane.promptUser}</span><span style={css("color:#6a6a74;")}>:</span><span style={css("color:#9a9aa3;")}>{pane.cwd}</span><span style={{ color: pane.promptColor, fontWeight: 600 }}>{"$ "}</span>
                            <input value={pane.input} onChange={pane.onInput} onKeyDown={pane.onKey} onFocus={pane.onActivate} ref={pane.setRef} spellCheck={false} autoComplete="off" style={css("flex:1;min-width:0;background:transparent;border:none;outline:none;color:inherit;caret-color:inherit;font:inherit;padding:0;")} />
                          </div>
                        </div>
                        )}
                      </div>
                    ))}
                  </div>
                  ))}

                  {/* SFTP PANEL */}
                  {v.sftpOpen && (
                    <div style={css("width:392px;flex:none;margin-left:10px;background:#0b0b0e;border:1px solid #1c1c24;border-radius:9px;display:flex;flex-direction:column;overflow:hidden;animation:acaRise .2s ease;")}>
                      <div style={css("display:flex;align-items:center;gap:9px;padding:11px 13px;border-bottom:1px solid #16161c;")}>
                        <span style={css("color:#ff7a59;")}>⇅</span>
                        <span style={css("font-size:12px;font-weight:600;color:#ededf0;")}>SFTP</span>
                        <span style={css("font-size:10px;color:#54545e;")}>·&nbsp;drag files between panes</span>
                        <span style={css("flex:1;")}></span>
                        <Hov onClick={v.toggleSftp} s="width:18px;height:18px;display:flex;align-items:center;justify-content:center;color:#54545e;border-radius:4px;cursor:pointer;" h="background:#222;color:#ededf0;">×</Hov>
                      </div>
                      {v.sftpReady ? (
                      <div style={css("flex:1;min-height:0;display:flex;gap:9px;padding:11px;")}>
                        <div onDragOver={v.onDragOver} onDrop={v.onDropLocal} onDragEnter={v.onDragEnterLocal} onDragLeave={v.onDragLeave} style={v.localColStyle}>
                          <div style={css("padding:8px 10px;border-bottom:1px solid #16161c;")}>
                            <div style={css("font-size:9px;letter-spacing:.12em;color:#54545e;text-transform:uppercase;")}>Local</div>
                            <div style={css("font-size:10.5px;color:#9a9aa3;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{v.localPath}</div>
                          </div>
                          <div style={css("flex:1;overflow:auto;padding:5px;")}>
                            {v.localFiles.map((file, i) => (
                              <Hov key={i} draggable={!file.isUp} onDragStart={file.onDragStart} onClick={file.onClick} onDoubleClick={file.onDouble || undefined} s={file.rowStyle} h="background:#15151b;">
                                <span style={{ color: file.glyphColor, width: "11px", textAlign: "center", flex: "none" }}>{file.glyph}</span>
                                <span style={css("flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{file.name}</span>
                                <span style={css("color:#54545e;font-size:10px;")}>{file.sub}</span>
                              </Hov>
                            ))}
                          </div>
                        </div>
                        <div onDragOver={v.onDragOver} onDrop={v.onDropRemote} onDragEnter={v.onDragEnterRemote} onDragLeave={v.onDragLeave} style={v.remoteColStyle}>
                          <div style={css("padding:8px 10px;border-bottom:1px solid #16161c;")}>
                            <div style={css("font-size:9px;letter-spacing:.12em;color:#ff7a59;text-transform:uppercase;")}>Remote · {v.sftpHost}</div>
                            <div style={css("font-size:10.5px;color:#9a9aa3;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{v.remotePath}</div>
                          </div>
                          <div style={css("flex:1;overflow:auto;padding:5px;")}>
                            {v.remoteFiles.map((file, i) => (
                              <Hov key={i} draggable={!file.isUp} onDragStart={file.onDragStart} onClick={file.onClick} onDoubleClick={file.onDouble || undefined} s={file.rowStyle} h="background:#15151b;">
                                <span style={{ color: file.glyphColor, width: "11px", textAlign: "center", flex: "none" }}>{file.glyph}</span>
                                <span style={css("flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{file.name}</span>
                                <span style={css("color:#54545e;font-size:10px;")}>{file.sub}</span>
                              </Hov>
                            ))}
                          </div>
                        </div>
                      </div>
                      ) : (
                        <div style={css("flex:1;min-height:0;display:flex;align-items:center;justify-content:center;text-align:center;font-size:11.5px;color:#6a6a74;padding:20px;")}>{v.sftpMsg}</div>
                      )}
                      {v.transferActive && (
                        <div style={css("padding:11px 13px;border-top:1px solid #16161c;")}>
                          <div style={css("display:flex;align-items:center;margin-bottom:7px;")}>
                            <span style={css("color:#ff7a59;margin-right:7px;")}>{v.transfer.arrow}</span>
                            <span style={css("font-size:11px;color:#cfcfd6;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{v.transfer.name}{v.transfer.queued > 0 ? ` · +${v.transfer.queued} queued` : ''}</span>
                            <span style={css("font-size:11px;color:#9a9aa3;")}>{v.transfer.pctLabel}</span>
                          </div>
                          <div style={css("height:4px;background:#16161c;border-radius:4px;overflow:hidden;")}>
                            <div style={v.transfer.fillStyle}></div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* STATUS BAR */}
            <div style={css("height:26px;flex:none;display:flex;align-items:center;gap:14px;padding:0 13px;background:#0a0a0d;border-top:1px solid #16161c;font-size:10.5px;color:#6a6a74;")}>
              <span style={css("display:flex;align-items:center;gap:6px;color:#9a9aa3;")}><span style={css("width:6px;height:6px;border-radius:2px;transform:rotate(45deg);background:#ff7a59;")}></span>main</span>
              <span>theme · {v.statusTheme}</span>
              <span>{v.statusHost}</span>
              {v.forwardCount > 0 && (<span style={css("color:#46d9a0;")}>⇄ {v.forwardCount} fwd</span>)}
              <span style={css("flex:1;")}></span>
              <span>UTF-8</span>
              <span>LF</span>
              <span style={css("color:#46d9a0;")}>● ready</span>
            </div>
          </div>
        </div>

        {/* COMMAND PALETTE */}
        {v.paletteOpen && (
          <div onClick={v.closePalette} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:flex-start;justify-content:center;padding-top:92px;z-index:60;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:580px;max-width:90%;background:#0e0e13;border:1px solid #26262e;border-radius:13px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .16s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("display:flex;align-items:center;gap:11px;padding:14px 16px;border-bottom:1px solid #18181f;")}>
                <span style={css("color:#ff7a59;")}>›</span>
                <input value={v.paletteQuery} onChange={v.setPaletteQuery} ref={v.paletteRef} placeholder="Search commands, hosts, themes…" spellCheck={false} style={css("flex:1;background:transparent;border:none;outline:none;color:#ededf0;font:inherit;font-size:14px;")} />
                <span style={css("font-size:10px;color:#54545e;border:1px solid #26262e;border-radius:4px;padding:1px 6px;")}>esc</span>
              </div>
              <div style={css("max-height:320px;overflow:auto;")}>
                {v.paletteItems.map((it, i) => (
                  <Hov key={i} onClick={it.onRun} s="display:flex;align-items:center;gap:11px;padding:11px 16px;cursor:pointer;" h="background:#16161c;">
                    <span style={{ color: it.iconColor, width: "14px", textAlign: "center" }}>{it.icon}</span>
                    <span style={css("flex:1;font-size:12.5px;color:#dcdce2;")}>{it.name}</span>
                    <span style={css("font-size:10.5px;color:#54545e;")}>{it.hint}</span>
                  </Hov>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* THEMES BROWSER */}
        {v.themesOpen && (
          <div onClick={v.closeThemes} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:40px;z-index:60;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:760px;max-width:96%;max-height:88vh;display:flex;flex-direction:column;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("display:flex;align-items:center;gap:11px;padding:18px 22px;border-bottom:1px solid #18181f;")}>
                <div>
                  <div style={css("font-size:15px;font-weight:700;color:#f2f2f5;")}>Community Themes</div>
                  <div style={css("font-size:11px;color:#6a6a74;margin-top:2px;")}>{v.themesCount} themes · installed locally · click to apply instantly</div>
                </div>
                <span style={css("flex:1;")}></span>
                <Hov onClick={v.closeThemes} s="width:26px;height:26px;display:flex;align-items:center;justify-content:center;color:#8b8b95;border:1px solid #26262e;border-radius:6px;cursor:pointer;" h="background:#16161c;color:#ededf0;">×</Hov>
              </div>
              <div style={css("flex:1;overflow:auto;padding:18px 22px;display:grid;grid-template-columns:repeat(3,1fr);gap:14px;")}>
                {v.themesList.map((th) => (
                  <div key={th.id} onClick={th.onApply} style={th.cardStyle}>
                    <div style={{ height: "62px", borderRadius: "7px", background: th.bg, padding: "9px", display: "flex", flexDirection: "column", gap: "5px", justifyContent: "center" }}>
                      <div style={{ height: "5px", width: "58%", borderRadius: "3px", background: th.accent }}></div>
                      <div style={{ height: "5px", width: "82%", borderRadius: "3px", background: th.fg, opacity: 0.72 }}></div>
                      <div style={{ height: "5px", width: "44%", borderRadius: "3px", background: th.fg, opacity: 0.4 }}></div>
                    </div>
                    <div style={css("display:flex;align-items:center;margin-top:11px;")}>
                      <span style={css("font-size:12.5px;font-weight:600;color:#ededf0;flex:1;")}>{th.name}</span>
                      {th.active && (<span style={css("font-size:9px;letter-spacing:.1em;color:#ff7a59;border:1px solid rgba(255,122,89,.35);border-radius:4px;padding:1px 6px;")}>ACTIVE</span>)}
                    </div>
                    <div style={css("font-size:10.5px;color:#6a6a74;margin-top:3px;")}>by {th.author}</div>
                    <div style={css("display:flex;gap:4px;margin-top:10px;")}>
                      {th.sw.map((sw, si) => (
                        <span key={si} style={{ width: "16px", height: "16px", borderRadius: "4px", background: sw, border: "1px solid rgba(255,255,255,.06)" }}></span>
                      ))}
                      <span style={css("flex:1;")}></span>
                      <span style={css("font-size:10px;color:#54545e;align-self:center;")}>↓ {th.downloads}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ABOUT / AUTHOR */}
        {v.aboutOpen && (
          <div onClick={v.closeAbout} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:40px;z-index:66;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:420px;max-width:96%;display:flex;flex-direction:column;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("display:flex;align-items:center;gap:11px;padding:16px 20px;border-bottom:1px solid #18181f;")}>
                <span style={css("font-size:13px;font-weight:700;color:#f2f2f5;")}>About</span>
                <span style={css("flex:1;")}></span>
                <Hov onClick={v.closeAbout} s="width:26px;height:26px;display:flex;align-items:center;justify-content:center;color:#8b8b95;border:1px solid #26262e;border-radius:6px;cursor:pointer;" h="background:#16161c;color:#ededf0;">×</Hov>
              </div>
              <div style={css("padding:26px 22px 24px;display:flex;flex-direction:column;align-items:center;text-align:center;")}>
                <img src={logoMark} width="80" height="80" alt="SSH Ache" style={{ borderRadius: "22px", boxShadow: "0 0 32px rgba(255,77,112,.42)" }} />
                <div style={css("font-size:17px;font-weight:700;color:#f2f2f5;margin-top:15px;")}>{v.author.name}</div>
                <div style={css("font-size:11.5px;color:#6a6a74;margin-top:3px;")}>Author &amp; developer of SSH&nbsp;Ache</div>
                <div style={css("position:relative;margin-top:18px;padding:15px 18px 14px;background:#0e0e12;border:1px solid #1c1c24;border-radius:12px;")}>
                  <span style={css("position:absolute;top:-12px;left:12px;font-family:Georgia,'Times New Roman',serif;font-size:34px;line-height:1;color:#ff5f6d;opacity:.55;")}>&ldquo;</span>
                  <div style={{ ...css("font-size:13px;font-style:italic;line-height:1.62;font-weight:600;"), background: "linear-gradient(120deg,#ff8a63,#ff5f6d,#ff3d7f)", WebkitBackgroundClip: "text", backgroundClip: "text", WebkitTextFillColor: "transparent" }}>{v.author.motto}</div>
                </div>
                <div style={css("display:flex;gap:8px;margin-top:20px;width:100%;")}>
                  <Hov as="button" onClick={() => v.openExt(v.author.github)} s="flex:1;padding:9px 8px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;" h="background:#16161c;color:#ededf0;">GitHub</Hov>
                  <Hov as="button" onClick={() => v.openExt('mailto:' + v.author.email)} s="flex:1;padding:9px 8px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Email</Hov>
                  <Hov as="button" onClick={() => v.openExt(v.author.site)} s="flex:1;padding:9px 8px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Website</Hov>
                </div>
                <Hov as="button" onClick={() => v.openExt(v.author.tip)} s="margin-top:11px;width:100%;padding:11px;background:linear-gradient(135deg,#ff7a59,#ff4f7a);border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:700;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:7px;" h="filter:brightness(1.06);">☕&nbsp;Buy me a coffee</Hov>
                <div style={css("font-size:10px;color:#54545e;margin-top:14px;")}>SSH&nbsp;Ache · v0.4.0</div>
              </div>
            </div>
          </div>
        )}

        {/* CONNECTION LOADER */}
        {v.connectingActive && (
          <div style={css("position:absolute;inset:0;background:rgba(5,5,7,.72);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;z-index:70;animation:acaFade .12s ease;")}>
            <div style={v.connectingCardStyle}>
              <div style={css("position:relative;width:88px;height:88px;margin:0 auto 18px;display:flex;align-items:center;justify-content:center;")}>
                <span style={v.connecting.ringStyle}></span>
                <span style={v.connecting.ring2Style}></span>
                <span style={v.connecting.spinnerStyle}></span>
                <span style={v.connecting.coreStyle}></span>
              </div>
              <div style={css("text-align:center;font-size:14px;font-weight:600;color:#f2f2f5;")}>{v.connecting.titleText}</div>
              <div style={css("text-align:center;font-size:11.5px;color:#6a6a74;margin-top:4px;")}>{v.connecting.target}</div>
              <div style={css("margin-top:18px;display:flex;flex-direction:column;gap:2px;")}>
                {v.connecting.steps.map((step, i) => (
                  <div key={i} style={css("display:flex;align-items:center;gap:11px;padding:5px 2px;")}>
                    {step.active && (<span style={css("width:14px;height:14px;border-radius:50%;border:2px solid #2a2a33;border-top-color:#ff7a59;animation:acaSpin .8s linear infinite;flex:none;")}></span>)}
                    {step.notActive && (<span style={{ width: "14px", height: "14px", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "11px", color: step.glyphColor, flex: "none" }}>{step.glyph}</span>)}
                    <span style={{ fontSize: "11.5px", color: step.labelColor }}>{step.label}</span>
                  </div>
                ))}
              </div>
              <Hov as="button" onClick={v.cancelConnect} s="margin-top:18px;width:100%;padding:8px;background:#121217;border:1px solid #26262e;border-radius:7px;color:#9a9aa3;font:inherit;font-size:11.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Cancel</Hov>
            </div>
          </div>
        )}

        {/* ADD HOST */}
        {v.addHostOpen && (
          <div onClick={v.closeAddHost} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:65;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:560px;max-width:96%;max-height:90vh;display:flex;flex-direction:column;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("display:flex;align-items:center;gap:11px;padding:18px 22px;border-bottom:1px solid #18181f;")}>
                <span style={css("width:14px;height:14px;background:#ff7a59;border-radius:3px;transform:rotate(45deg);flex:none;")}></span>
                <div style={css("flex:1;")}>
                  <div style={css("font-size:15px;font-weight:700;color:#f2f2f5;")}>{v.modalTitle}</div>
                  <div style={css("font-size:11px;color:#6a6a74;margin-top:1px;")}>{v.modalSubtitle}</div>
                </div>
                <Hov onClick={v.closeAddHost} s="width:26px;height:26px;display:flex;align-items:center;justify-content:center;color:#8b8b95;border:1px solid #26262e;border-radius:6px;cursor:pointer;" h="background:#16161c;color:#ededf0;">×</Hov>
              </div>
              <div style={css("flex:1;overflow:auto;padding:20px 22px;display:flex;flex-direction:column;gap:16px;")}>
                <div>
                  <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Label</div>
                  <Hov as="input" value={v.fName} onChange={v.onFName} placeholder="e.g. production-web" spellCheck={false} s="width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                </div>
                <div style={css("display:flex;gap:12px;")}>
                  <div style={css("flex:1;")}>
                    <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Host / IP</div>
                    <Hov as="input" value={v.fHost} onChange={v.onFHost} placeholder="10.0.0.5 or example.com" spellCheck={false} s="width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                  </div>
                  <div style={css("width:92px;flex:none;")}>
                    <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Port</div>
                    <Hov as="input" value={v.fPort} onChange={v.onFPort} placeholder="22" spellCheck={false} s="width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                  </div>
                </div>
                <div>
                  <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Username</div>
                  <Hov as="input" value={v.fUser} onChange={v.onFUser} placeholder="root" spellCheck={false} s="width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                </div>
                <div>
                  <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Authentication</div>
                  <div style={css("display:flex;gap:7px;")}>
                    <div onClick={v.setAuthPassword} style={v.authPwStyle}>Password</div>
                    <div onClick={v.setAuthKey} style={v.authKeyStyle}>Key file</div>
                    <div onClick={v.setAuthAgent} style={v.authAgentStyle}>SSH agent</div>
                  </div>
                  {v.authIsPassword && (
                    <Hov as="input" value={v.fPassword} onChange={v.onFPassword} type="password" placeholder="Password (stored encrypted)" s="width:100%;margin-top:10px;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                  )}
                  {v.authIsKey && (
                    <div style={css("margin-top:10px;display:flex;flex-direction:column;gap:9px;")}>
                      <div style={css("display:flex;gap:6px;padding:4px;background:#0e0e12;border:1px solid #20202a;border-radius:8px;")}>
                        <div onClick={v.setKeyModeFile} style={v.keyFileStyle}>File path</div>
                        <div onClick={v.setKeyModeText} style={v.keyTextStyle}>Paste text</div>
                      </div>
                      {v.keyModeFile && (
                        <div style={css("display:flex;flex-direction:column;gap:9px;")}>
                          <div style={css("display:flex;gap:8px;")}>
                            <Hov as="input" value={v.fKeyPath} onChange={v.onFKeyPath} placeholder="~/.ssh/id_ed25519" spellCheck={false} s="flex:1;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                            <Hov as="button" onClick={v.onBrowseKey} s="flex:none;padding:0 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Browse…</Hov>
                          </div>
                          <Hov as="input" value={v.fPassphrase} onChange={v.onFPassphrase} type="password" placeholder="Key passphrase (optional)" s="width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                        </div>
                      )}
                      {v.keyModeText && (
                        <div style={css("display:flex;flex-direction:column;gap:0;")}>
                          <textarea value={v.fKeyText} onChange={v.onFKeyText} placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA…\n-----END OPENSSH PRIVATE KEY-----"} spellCheck={false} style={v.keyTextAreaStyle}></textarea>
                          {v.keyShowStatus && (
                            <div style={v.keyStatusStyle}>
                              <span style={v.keyIconStyle}>{v.keyStatusIcon}</span>
                              <span>{v.keyStatusMsg}</span>
                            </div>
                          )}
                          <Hov as="input" value={v.fPassphrase} onChange={v.onFPassphrase} type="password" placeholder="Key passphrase (optional)" s="width:100%;margin-top:9px;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                        </div>
                      )}
                    </div>
                  )}
                  {v.authIsAgent && (
                    <div style={css("margin-top:10px;font-size:11.5px;color:#6a6a74;padding:11px 13px;background:#0e0e12;border:1px solid #20202a;border-radius:8px;")}>Uses your running ssh-agent identities. No secrets stored.</div>
                  )}
                </div>
                <div>
                  <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Folder</div>
                  <Hov as="input" value={v.fFolder} onChange={v.onFFolder} placeholder="Production, Personal, …" spellCheck={false} s="width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                  <div style={css("display:flex;flex-wrap:wrap;gap:6px;margin-top:9px;")}>
                    {v.folderChips.map((fc, i) => (
                      <Hov key={i} onClick={fc.onPick} s="font-size:10.5px;color:#9a9aa3;background:#101015;border:1px solid #20202a;border-radius:6px;padding:4px 9px;cursor:pointer;" h="border-color:rgba(255,122,89,.4);color:#ededf0;">{fc.name}</Hov>
                    ))}
                  </div>
                </div>
                <div>
                  <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Tags</div>
                  <Hov as="input" value={v.fTagInput} onChange={v.onFTagInput} onKeyDown={v.onFTagKey} placeholder="Type a tag and press Enter" spellCheck={false} s="width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                  <div style={css("display:flex;flex-wrap:wrap;gap:6px;margin-top:9px;")}>
                    {v.fTags.map((tg, i) => (
                      <span key={i} style={css("display:flex;align-items:center;gap:6px;font-size:11px;color:#ff7a59;background:rgba(255,122,89,.1);border:1px solid rgba(255,122,89,.35);border-radius:6px;padding:4px 6px 4px 9px;")}>#{tg.name}<span onClick={tg.onRemove} style={css("cursor:pointer;color:#ff7a59;opacity:.7;font-size:13px;line-height:1;")}>×</span></span>
                    ))}
                  </div>
                </div>
              </div>
              <div style={css("flex:none;display:flex;align-items:center;gap:10px;padding:16px 22px;border-top:1px solid #18181f;")}>
                {v.isEditing && (
                  <Hov as="button" onClick={v.deleteHost} s="padding:10px 14px;background:transparent;border:1px solid rgba(255,107,120,.35);border-radius:8px;color:#ff6b78;font:inherit;font-size:12.5px;cursor:pointer;" h="background:rgba(255,107,120,.1);">Delete</Hov>
                )}
                <span style={css("font-size:10.5px;color:#54545e;")}>⚿ encrypted on disk</span>
                <span style={css("flex:1;")}></span>
                <Hov as="button" onClick={v.closeAddHost} s="padding:10px 16px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Cancel</Hov>
                <button onClick={v.saveHost} style={v.saveHostStyle}>{v.saveLabel}</button>
              </div>
            </div>
          </div>
        )}

        {/* SETTINGS */}
        {v.settingsOpen && (
          <div onClick={v.closeSettings} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:65;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:600px;max-width:96%;max-height:90vh;display:flex;flex-direction:column;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("display:flex;align-items:center;gap:11px;padding:18px 22px;border-bottom:1px solid #18181f;")}>
                <div style={css("flex:1;")}>
                  <div style={css("font-size:15px;font-weight:700;color:#f2f2f5;")}>Settings</div>
                  <div style={css("font-size:11px;color:#6a6a74;margin-top:1px;")}>Preferences saved locally to ~/.ssh-ache/state.json</div>
                </div>
                <Hov onClick={v.closeSettings} s="width:26px;height:26px;display:flex;align-items:center;justify-content:center;color:#8b8b95;border:1px solid #26262e;border-radius:6px;cursor:pointer;" h="background:#16161c;color:#ededf0;">×</Hov>
              </div>
              <div style={css("flex:1;overflow:auto;padding:20px 22px;display:flex;flex-direction:column;gap:24px;")}>

                <div>
                  <div style={css("font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#ff7a59;margin-bottom:12px;")}>Appearance</div>
                  <div style={css("font-size:12px;color:#cfcfd6;margin-bottom:9px;")}>Default theme</div>
                  <div style={css("display:grid;grid-template-columns:repeat(4,1fr);gap:8px;")}>
                    {v.themeOptions.map((th) => (
                      <div key={th.id} onClick={th.onPick} style={th.style}>
                        <span style={th.dotStyle}></span>
                        <span style={css("overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{th.name}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div style={css("font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#ff7a59;margin-bottom:12px;")}>Terminal</div>
                  <div style={css("display:flex;align-items:center;gap:12px;margin-bottom:16px;")}>
                    <span style={css("flex:1;font-size:12px;color:#cfcfd6;")}>Font size</span>
                    <input type="range" min="11" max="18" step="1" value={v.fontSize} onChange={v.onFontSize} style={css("width:180px;accent-color:#ff7a59;")} />
                    <span style={css("font-size:11px;color:#9a9aa3;width:34px;text-align:right;")}>{v.fontSizeLabel}</span>
                  </div>
                  <div style={css("display:flex;align-items:center;gap:12px;margin-bottom:16px;")}>
                    <span style={css("flex:1;font-size:12px;color:#cfcfd6;")}>Cursor</span>
                    <div style={css("display:flex;gap:6px;width:280px;")}>
                      <div onClick={v.setCursorBlock} style={v.cursorBlockStyle}>Block</div>
                      <div onClick={v.setCursorBar} style={v.cursorBarStyle}>Bar</div>
                      <div onClick={v.setCursorUnder} style={v.cursorUnderStyle}>Underline</div>
                    </div>
                  </div>
                  <div style={css("display:flex;align-items:center;gap:12px;")}>
                    <span style={css("flex:1;font-size:12px;color:#cfcfd6;")}>Scrollback (lines)</span>
                    <Hov as="input" value={v.scrollback} onChange={v.onScrollback} s="width:120px;background:#0e0e12;border:1px solid #20202a;border-radius:7px;padding:8px 11px;color:#ededf0;font:inherit;font-size:12px;outline:none;" f="border-color:rgba(255,122,89,.5);" />
                  </div>
                </div>

                <div>
                  <div style={css("font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#ff7a59;margin-bottom:12px;")}>Behaviour &amp; Security</div>
                  <div style={css("display:flex;align-items:center;gap:12px;margin-bottom:14px;")}>
                    <div style={css("flex:1;")}><div style={css("font-size:12px;color:#cfcfd6;")}>Confirm before closing a session</div></div>
                    <div onClick={v.toggleConfirmClose} style={v.confirmCloseTrack}><span style={v.confirmCloseKnob}></span></div>
                  </div>
                  <div style={css("display:flex;align-items:center;gap:12px;margin-bottom:14px;")}>
                    <div style={css("flex:1;")}><div style={css("font-size:12px;color:#cfcfd6;")}>Restore tabs on launch</div></div>
                    <div onClick={v.toggleRestoreTabs} style={v.restoreTabsTrack}><span style={v.restoreTabsKnob}></span></div>
                  </div>
                  <div style={css("display:flex;align-items:center;gap:12px;")}>
                    <div style={css("flex:1;")}><div style={css("font-size:12px;color:#cfcfd6;")}>Lock vault after idle</div><div style={css("font-size:10.5px;color:#54545e;margin-top:2px;")}>Re-enter passphrase after 15 min</div></div>
                    <div onClick={v.toggleLockIdle} style={v.lockIdleTrack}><span style={v.lockIdleKnob}></span></div>
                  </div>
                </div>

                <div>
                  <div style={css("font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#ff7a59;margin-bottom:12px;")}>AI agent access</div>
                  <div style={css("display:flex;align-items:center;gap:10px;padding:12px 14px;background:#0e0e12;border:1px solid #1c1c24;border-radius:9px;")}>
                    <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: v.mcpRunning ? '#46d9a0' : '#54545e', flex: 'none' }}></span>
                    <div style={css("flex:1;")}>
                      <div style={css("font-size:11.5px;color:#cfcfd6;")}>MCP server {v.mcpRunning ? '· running' : '· stopped'}</div>
                      <div style={css("font-size:10.5px;color:#54545e;margin-top:2px;")}>Let an AI agent use selected hosts, with per-command approval.</div>
                    </div>
                    <Hov as="button" onClick={v.openMcp} s="padding:7px 12px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Manage</Hov>
                  </div>
                </div>

                <div>
                  <div style={css("font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#ff7a59;margin-bottom:12px;")}>Local data</div>
                  <div style={css("display:flex;align-items:center;gap:10px;padding:12px 14px;background:#0e0e12;border:1px solid #1c1c24;border-radius:9px;")}>
                    <span style={css("width:7px;height:7px;border-radius:50%;background:#46d9a0;box-shadow:0 0 7px rgba(70,217,160,.6);flex:none;")}></span>
                    <span style={css("flex:1;font-size:11.5px;color:#9a9aa3;")}>Stored on this device, encrypted at rest</span>
                    <Hov as="button" onClick={v.onImport} s="padding:7px 12px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Import</Hov>
                    <Hov as="button" onClick={v.onExport} s="padding:7px 12px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Export</Hov>
                  </div>
                </div>

              </div>
              <div style={css("flex:none;display:flex;align-items:center;padding:14px 22px;border-top:1px solid #18181f;")}>
                <span style={css("font-size:10.5px;color:#54545e;")}>SSH Ache · v0.4.0</span>
                <span style={css("flex:1;")}></span>
                <Hov as="button" onClick={v.closeSettings} s="padding:9px 18px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Done</Hov>
              </div>
            </div>
          </div>
        )}

        {/* CONNECT SECRET PROMPT */}
        {v.secretPromptOpen && (
          <div onClick={v.cancelSecret} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:75;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:380px;max-width:94%;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("padding:18px 20px 4px;font-size:14px;font-weight:700;color:#f2f2f5;")}>{v.secretPromptTitle}</div>
              <div style={css("padding:8px 20px 18px;display:flex;flex-direction:column;gap:9px;")}>
                <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;")}>{v.secretPromptLabel}</div>
                <input value={v.secretValue} onChange={v.onSecretInput} onKeyDown={v.onSecretKey} type="password" autoFocus spellCheck={false} style={css("width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;")} />
                <div style={css("font-size:10.5px;color:#54545e;")}>{v.secretPromptHint}</div>
              </div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.cancelSecret} s="padding:9px 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Cancel</Hov>
                <Hov as="button" onClick={v.submitSecret} s="padding:9px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Connect</Hov>
              </div>
            </div>
          </div>
        )}

        {/* HOST KEY CONFIRM (first-seen) */}
        {v.hostKeyOpen && (
          <div onClick={v.rejectHostKey} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:75;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:460px;max-width:96%;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("display:flex;align-items:center;gap:11px;padding:18px 20px 8px;")}>
                <span style={css("width:26px;height:26px;flex:none;display:flex;align-items:center;justify-content:center;border-radius:7px;background:rgba(255,122,89,.12);color:#ff7a59;font-size:14px;")}>⚿</span>
                <div style={css("flex:1;")}>
                  <div style={css("font-size:14px;font-weight:700;color:#f2f2f5;")}>Unknown host key</div>
                  <div style={css("font-size:11px;color:#6a6a74;margin-top:1px;")}>{v.hostKeyName} · {v.hostKeyTarget}</div>
                </div>
              </div>
              <div style={css("padding:4px 20px 16px;display:flex;flex-direction:column;gap:10px;")}>
                <div style={css("font-size:12px;color:#cfcfd6;line-height:1.5;")}>First time connecting to this server. Verify the SHA256 fingerprint matches the server's real key before trusting it.</div>
                <div style={css("font-size:11.5px;color:#ededf0;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:10px 12px;word-break:break-all;")}>{v.hostKeyFp}</div>
                <div style={css("font-size:10.5px;color:#54545e;")}>Trusting adds it to ~/.ssh/known_hosts; you won't be asked again.</div>
              </div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.rejectHostKey} s="padding:9px 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Reject</Hov>
                <Hov as="button" onClick={v.acceptHostKey} s="padding:9px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Trust &amp; connect</Hov>
              </div>
            </div>
          </div>
        )}

        {/* EDIT FOLDER */}
        {v.folderEditOpen && (
          <div onClick={v.cancelFolderEdit} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:79;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:400px;max-width:94%;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("padding:18px 20px 4px;font-size:14px;font-weight:700;color:#f2f2f5;")}>Edit folder</div>
              <div style={css("padding:10px 20px 16px;display:flex;flex-direction:column;gap:14px;")}>
                <div>
                  <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Name</div>
                  <input value={v.folderEditName} onChange={v.onFolderEditName} autoFocus spellCheck={false} style={css("width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:10px 12px;color:#ededf0;font:inherit;font-size:13px;outline:none;")} />
                </div>
                <div>
                  <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:7px;")}>Color</div>
                  <div style={css("display:flex;gap:8px;flex-wrap:wrap;")}>
                    {v.folderPalette.map((c, i) => (
                      <span key={i} onClick={() => v.pickFolderColor(c)} style={{ width: '22px', height: '22px', borderRadius: '6px', background: c, cursor: 'pointer', border: '2px solid ' + (v.folderEditColor === c ? '#ededf0' : 'transparent'), boxShadow: '0 0 0 1px rgba(255,255,255,.08)' }}></span>
                    ))}
                  </div>
                </div>
                <div style={css("display:flex;align-items:center;gap:12px;")}>
                  <div style={css("flex:1;font-size:12px;color:#cfcfd6;")}>Favorite <span style={css("color:#54545e;")}>· show at top</span></div>
                  <div onClick={v.toggleFolderEditFav} style={{ width: '38px', height: '22px', borderRadius: '11px', background: v.folderEditFav ? '#ff7a59' : '#26262e', position: 'relative', cursor: 'pointer', flex: 'none' }}>
                    <span style={{ position: 'absolute', top: '2px', left: v.folderEditFav ? '18px' : '2px', width: '18px', height: '18px', borderRadius: '50%', background: '#fff', transition: 'left .15s ease' }}></span>
                  </div>
                </div>
              </div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.cancelFolderEdit} s="padding:9px 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Cancel</Hov>
                <Hov as="button" onClick={v.saveFolderEdit} s="padding:9px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Save</Hov>
              </div>
            </div>
          </div>
        )}

        {/* ADD PORT FORWARD */}
        {v.fwdOpen && (
          <div onClick={v.cancelForward} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:79;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:470px;max-width:96%;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("padding:18px 20px 4px;font-size:14px;font-weight:700;color:#f2f2f5;")}>Add port forward <span style={css("color:#6a6a74;font-weight:400;")}>(local · -L)</span></div>
              <div style={css("padding:10px 20px 16px;display:flex;flex-direction:column;gap:10px;")}>
                <div style={css("display:flex;align-items:flex-end;gap:8px;")}>
                  <div style={css("width:88px;")}>
                    <div style={css("font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:6px;")}>Local port</div>
                    <input value={v.fwdLocal} onChange={v.onFwdLocal} placeholder="8080" autoFocus spellCheck={false} style={css("width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:10px 11px;color:#ededf0;font:inherit;font-size:13px;outline:none;")} />
                  </div>
                  <span style={css("color:#54545e;padding-bottom:11px;")}>→</span>
                  <div style={css("flex:1;")}>
                    <div style={css("font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:6px;")}>Remote host</div>
                    <input value={v.fwdRemoteHost} onChange={v.onFwdRemoteHost} placeholder="127.0.0.1" spellCheck={false} style={css("width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:10px 11px;color:#ededf0;font:inherit;font-size:13px;outline:none;")} />
                  </div>
                  <span style={css("color:#54545e;padding-bottom:11px;")}>:</span>
                  <div style={css("width:88px;")}>
                    <div style={css("font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;margin-bottom:6px;")}>Remote port</div>
                    <input value={v.fwdRemotePort} onChange={v.onFwdRemotePort} placeholder="5432" spellCheck={false} style={css("width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:10px 11px;color:#ededf0;font:inherit;font-size:13px;outline:none;")} />
                  </div>
                </div>
                <div style={css("font-size:10.5px;color:#54545e;line-height:1.5;")}>Connections to <span style={css("color:#9a9aa3;")}>localhost:{v.fwdLocal || '…'}</span> tunnel to <span style={css("color:#9a9aa3;")}>{v.fwdRemoteHost || '…'}:{v.fwdRemotePort || '…'}</span> over this SSH session.</div>
              </div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.cancelForward} s="padding:9px 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Cancel</Hov>
                <Hov as="button" onClick={v.submitForward} s="padding:9px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Start forward</Hov>
              </div>
            </div>
          </div>
        )}

        {/* SET VAULT PASSPHRASE */}
        {v.lockSetOpen && (
          <div onClick={v.cancelLockSet} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:79;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:380px;max-width:94%;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("padding:18px 20px 4px;font-size:14px;font-weight:700;color:#f2f2f5;")}>Set a vault passphrase</div>
              <div style={css("padding:8px 20px 18px;display:flex;flex-direction:column;gap:9px;")}>
                <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;")}>Passphrase</div>
                <input value={v.lockSetValue} onChange={v.onLockSetInput} onKeyDown={v.onLockSetKey} type="password" autoFocus spellCheck={false} style={css("width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;")} />
                <div style={css("font-size:10.5px;color:#54545e;line-height:1.5;")}>Required to unlock after 15 min idle. Stored as a hash — not recoverable.</div>
              </div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.cancelLockSet} s="padding:9px 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Cancel</Hov>
                <Hov as="button" onClick={v.submitLockSet} s="padding:9px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Enable lock</Hov>
              </div>
            </div>
          </div>
        )}

        {/* VAULT LOCKED */}
        {v.locked && (
          <div style={css("position:absolute;inset:0;background:#09090b;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;z-index:95;animation:acaFade .15s ease;")}>
            <span style={css("width:34px;height:34px;background:#ff7a59;border-radius:8px;transform:rotate(45deg);box-shadow:0 0 24px rgba(255,122,89,.5);")}></span>
            <div style={css("font-size:16px;font-weight:700;color:#f2f2f5;margin-top:6px;")}>SSH Ache is locked</div>
            <div style={css("font-size:11.5px;color:#6a6a74;")}>Enter your vault passphrase to unlock.</div>
            <div style={css("display:flex;gap:8px;margin-top:4px;")}>
              <input value={v.unlockValue} onChange={v.onUnlockInput} onKeyDown={v.onUnlockKey} type="password" autoFocus spellCheck={false} placeholder="Passphrase" style={css("width:240px;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;")} />
              <Hov as="button" onClick={v.submitUnlock} s="padding:11px 18px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Unlock</Hov>
            </div>
          </div>
        )}

        {/* IMPORT / EXPORT PASSWORD */}
        {v.ioOpen && (
          <div onClick={v.ioCancel} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:79;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:400px;max-width:94%;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("padding:18px 20px 4px;font-size:14px;font-weight:700;color:#f2f2f5;")}>{v.ioTitle}</div>
              <div style={css("padding:8px 20px 18px;display:flex;flex-direction:column;gap:9px;")}>
                <div style={css("font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#6a6a74;")}>{v.ioLabel}</div>
                <input value={v.ioValue} onChange={v.onIoInput} onKeyDown={v.onIoKey} type="password" autoFocus spellCheck={false} style={css("width:100%;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;color:#ededf0;font:inherit;font-size:13px;outline:none;")} />
                <div style={css("font-size:10.5px;color:#54545e;line-height:1.5;")}>{v.ioHint}</div>
              </div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.ioCancel} s="padding:9px 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Cancel</Hov>
                <Hov as="button" onClick={v.ioSubmit} s="padding:9px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">{v.ioCta}</Hov>
              </div>
            </div>
          </div>
        )}

        {/* CONFIRM CLOSE SESSION */}
        {v.confirmCloseOpen && (
          <div onClick={v.cancelConfirmClose} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:78;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:380px;max-width:94%;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("padding:18px 20px 4px;font-size:14px;font-weight:700;color:#f2f2f5;")}>Close session?</div>
              <div style={css("padding:8px 20px 18px;font-size:12px;color:#cfcfd6;line-height:1.5;")}>End the SSH connection to <span style={css("color:#ededf0;font-weight:600;")}>{v.confirmCloseName}</span>? Any running command stops.</div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.cancelConfirmClose} s="padding:9px 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Cancel</Hov>
                <Hov as="button" onClick={v.confirmCloseTab} s="padding:9px 16px;background:transparent;border:1px solid rgba(255,107,120,.45);border-radius:8px;color:#ff6b78;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:rgba(255,107,120,.12);">Close session</Hov>
              </div>
            </div>
          </div>
        )}

        {/* MCP — AI AGENT ACCESS */}
        {v.mcpOpen && (
          <div onClick={v.closeMcp} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:40px;z-index:66;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:660px;max-width:96%;max-height:88vh;display:flex;flex-direction:column;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("display:flex;align-items:center;gap:11px;padding:18px 22px;border-bottom:1px solid #18181f;")}>
                <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: v.mcpRunning ? '#46d9a0' : '#54545e', boxShadow: v.mcpRunning ? '0 0 7px rgba(70,217,160,.6)' : 'none', flex: 'none' }}></span>
                <div style={css("flex:1;")}>
                  <div style={css("font-size:15px;font-weight:700;color:#f2f2f5;")}>AI agent access · MCP</div>
                  <div style={css("font-size:11px;color:#6a6a74;margin-top:2px;")}>{v.mcpRunning ? 'Running on 127.0.0.1' : 'Stopped'} · {v.mcpExposedCount} host(s) exposed</div>
                </div>
                <Hov as="button" onClick={v.toggleMcp} s={v.mcpRunning ? "padding:8px 16px;background:transparent;border:1px solid rgba(255,107,120,.4);border-radius:8px;color:#ff6b78;font:inherit;font-size:12px;cursor:pointer;" : "padding:8px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12px;font-weight:600;cursor:pointer;"} h={v.mcpRunning ? "background:rgba(255,107,120,.12);" : "background:#ff8d70;"}>{v.mcpRunning ? 'Stop' : 'Start'}</Hov>
                <span onClick={v.closeMcp} style={css("width:26px;height:26px;display:flex;align-items:center;justify-content:center;color:#8b8b95;border:1px solid #26262e;border-radius:6px;cursor:pointer;")}>×</span>
              </div>
              <div style={css("flex:1;overflow:auto;padding:18px 22px;display:flex;flex-direction:column;gap:20px;")}>
                <div style={css("display:flex;gap:9px;padding:11px 13px;background:rgba(70,217,160,.05);border:1px solid rgba(70,217,160,.2);border-radius:9px;")}>
                  <span style={css("color:#46d9a0;flex:none;")}>⚿</span>
                  <div style={css("font-size:11px;color:#9a9aa3;line-height:1.55;")}>Bound to <span style={css("color:#cfcfd6;")}>localhost</span> behind a bearer token. Only the hosts you enable below are visible. <span style={css("color:#cfcfd6;")}>Every command needs your approval.</span> Secrets are never sent to the agent.</div>
                </div>

                {v.mcpRunning && (
                  <div style={css("display:flex;flex-direction:column;gap:10px;")}>
                    <div style={css("font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#ff7a59;")}>Connection</div>
                    <div style={css("display:flex;align-items:center;gap:8px;")}>
                      <span style={css("font-size:10.5px;color:#6a6a74;width:48px;flex:none;")}>URL</span>
                      <span style={css("flex:1;font-size:11.5px;color:#ededf0;background:#0e0e12;border:1px solid #20202a;border-radius:7px;padding:8px 11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{v.mcpUrl}</span>
                      <Hov as="button" onClick={() => v.copyMcp(v.mcpUrl)} s="padding:8px 11px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;flex:none;" h="background:#16161c;color:#ededf0;">Copy</Hov>
                    </div>
                    <div style={css("display:flex;align-items:center;gap:8px;")}>
                      <span style={css("font-size:10.5px;color:#6a6a74;width:48px;flex:none;")}>Token</span>
                      <span style={css("flex:1;font-size:11.5px;color:#9a9aa3;background:#0e0e12;border:1px solid #20202a;border-radius:7px;padding:8px 11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{v.mcpToken.slice(0, 8)}…{v.mcpToken.slice(-4)}</span>
                      <Hov as="button" onClick={() => v.copyMcp(v.mcpToken)} s="padding:8px 11px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;flex:none;" h="background:#16161c;color:#ededf0;">Copy</Hov>
                    </div>
                    <div style={css("display:flex;align-items:flex-start;gap:8px;")}>
                      <span style={css("font-size:10.5px;color:#6a6a74;width:48px;flex:none;margin-top:8px;")}>Config</span>
                      <pre style={css("flex:1;margin:0;font-size:10.5px;color:#9a9aa3;background:#0e0e12;border:1px solid #20202a;border-radius:7px;padding:10px 12px;overflow:auto;white-space:pre;")}>{v.mcpConfig}</pre>
                      <Hov as="button" onClick={() => v.copyMcp(v.mcpConfig)} s="padding:8px 11px;background:#101015;border:1px solid #20202a;border-radius:7px;color:#b9b9c2;font:inherit;font-size:11px;cursor:pointer;flex:none;margin-top:0;" h="background:#16161c;color:#ededf0;">Copy</Hov>
                    </div>
                  </div>
                )}

                <div style={css("display:flex;flex-direction:column;gap:8px;")}>
                  <div style={css("font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#ff7a59;")}>Hosts the agent may use</div>
                  {v.mcpHosts.length === 0 && (<div style={css("font-size:11.5px;color:#54545e;")}>No hosts yet.</div>)}
                  {v.mcpHosts.map((h) => (
                    <div key={h.id} style={css("display:flex;align-items:center;gap:10px;padding:9px 12px;background:#0e0e12;border:1px solid #1c1c24;border-radius:8px;")}>
                      <div style={css("flex:1;min-width:0;")}>
                        <div style={css("font-size:12px;color:#ededf0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{h.name}</div>
                        <div style={css("font-size:10.5px;color:#6a6a74;margin-top:1px;")}>{h.target}</div>
                      </div>
                      <div onClick={h.onToggle} style={{ width: '38px', height: '22px', borderRadius: '11px', background: h.allowed ? '#46d9a0' : '#26262e', position: 'relative', cursor: 'pointer', flex: 'none' }}>
                        <span style={{ position: 'absolute', top: '2px', left: h.allowed ? '18px' : '2px', width: '18px', height: '18px', borderRadius: '50%', background: '#fff', transition: 'left .15s ease' }}></span>
                      </div>
                    </div>
                  ))}
                </div>

                <div style={css("display:flex;flex-direction:column;gap:6px;")}>
                  <div style={css("font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#ff7a59;")}>Recent activity</div>
                  {(!v.mcpLog || v.mcpLog.length === 0) && (<div style={css("font-size:11.5px;color:#54545e;")}>No commands yet.</div>)}
                  {(v.mcpLog || []).slice(-12).reverse().map((l, i) => (
                    <div key={i} style={css("display:flex;align-items:center;gap:8px;font-size:11px;padding:6px 2px;")}>
                      <span style={{ color: l.allowed ? '#46d9a0' : '#ff6b78', flex: 'none' }}>{l.allowed ? '✓' : '✕'}</span>
                      <span style={css("color:#9a9aa3;flex:none;")}>{l.host}</span>
                      <span style={css("color:#cfcfd6;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:inherit;")}>{l.command}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* MCP COMMAND APPROVAL */}
        {v.approvalOpen && (
          <div style={css("position:absolute;inset:0;background:rgba(5,5,7,.72);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:90;animation:acaFade .12s ease;")}>
            <div style={css("width:500px;max-width:96%;background:#0c0c10;border:1px solid rgba(255,122,89,.4);border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("display:flex;align-items:center;gap:11px;padding:18px 20px 8px;")}>
                <span style={css("width:26px;height:26px;flex:none;display:flex;align-items:center;justify-content:center;border-radius:7px;background:rgba(255,122,89,.12);color:#ff7a59;font-size:14px;")}>›_</span>
                <div style={css("flex:1;")}>
                  <div style={css("font-size:14px;font-weight:700;color:#f2f2f5;")}>Agent wants to run a command</div>
                  <div style={css("font-size:11px;color:#6a6a74;margin-top:1px;")}>on <span style={css("color:#cfcfd6;")}>{v.approvalHost}</span></div>
                </div>
              </div>
              <div style={css("padding:6px 20px 14px;")}>
                <pre style={css("margin:0;font-size:12px;color:#ededf0;background:#0e0e12;border:1px solid #20202a;border-radius:8px;padding:11px 13px;overflow:auto;white-space:pre-wrap;word-break:break-word;")}>{v.approvalCommand}</pre>
                <div style={css("font-size:10.5px;color:#54545e;margin-top:9px;")}>Approve only if you trust this command. It runs with this host's saved credentials.</div>
              </div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.deny} s="padding:9px 16px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Deny</Hov>
                <Hov as="button" onClick={v.approve} s="padding:9px 18px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Approve &amp; run</Hov>
              </div>
            </div>
          </div>
        )}

        {/* SFTP FILE-EXISTS CONFLICT */}
        {v.conflictOpen && (
          <div onClick={v.conflictSkip} style={css("position:absolute;inset:0;background:rgba(5,5,7,.6);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:32px;z-index:78;animation:acaFade .12s ease;")}>
            <div onClick={v.stop} style={css("width:420px;max-width:94%;background:#0c0c10;border:1px solid #26262e;border-radius:14px;box-shadow:0 36px 90px rgba(0,0,0,.65);overflow:hidden;animation:acaModal .18s cubic-bezier(.2,.8,.2,1);")}>
              <div style={css("padding:18px 20px 4px;font-size:14px;font-weight:700;color:#f2f2f5;")}>File already exists</div>
              <div style={css("padding:8px 20px 14px;font-size:12px;color:#cfcfd6;line-height:1.55;")}><span style={css("color:#ededf0;font-weight:600;")}>{v.conflictName}</span> already exists in <span style={css("color:#9a9aa3;")}>{v.conflictDest}</span>. Replace it or skip?</div>
              <div style={css("display:flex;align-items:center;gap:12px;padding:0 20px 14px;")}>
                <div style={css("flex:1;font-size:12px;color:#cfcfd6;")}>Apply to all</div>
                <div onClick={v.toggleConflictAll} style={{ width: '38px', height: '22px', borderRadius: '11px', background: v.conflictAll ? '#ff7a59' : '#26262e', position: 'relative', cursor: 'pointer', flex: 'none' }}>
                  <span style={{ position: 'absolute', top: '2px', left: v.conflictAll ? '18px' : '2px', width: '18px', height: '18px', borderRadius: '50%', background: '#fff', transition: 'left .15s ease' }}></span>
                </div>
              </div>
              <div style={css("display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #18181f;")}>
                <Hov as="button" onClick={v.conflictSkip} s="padding:9px 14px;background:#101015;border:1px solid #20202a;border-radius:8px;color:#b9b9c2;font:inherit;font-size:12.5px;cursor:pointer;" h="background:#16161c;color:#ededf0;">Skip</Hov>
                <Hov as="button" onClick={v.conflictReplace} s="padding:9px 16px;background:#ff7a59;border:none;border-radius:8px;color:#0c0b0a;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;" h="background:#ff8d70;">Replace</Hov>
              </div>
            </div>
          </div>
        )}

        {/* TOASTS */}
        <div style={css("position:absolute;right:18px;bottom:18px;display:flex;flex-direction:column;gap:10px;z-index:80;align-items:flex-end;")}>
          {v.toasts.map((t, i) => (
            <div key={i} style={t.style}>
              <span style={t.iconStyle}>{t.icon}</span>
              <div style={css("min-width:0;")}>
                <div style={css("font-size:12.5px;font-weight:600;color:#ededf0;")}>{t.title}</div>
                <div style={css("font-size:11px;color:#8b8b95;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{t.msg}</div>
              </div>
            </div>
          ))}
        </div>

      </div>
    );
  }
}
