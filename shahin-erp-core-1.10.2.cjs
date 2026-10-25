/* Shahin ERP — Windows desktop app (Electron main process).
   Data lives in one JSON file. Portable copies (USB) keep data next to the program.
   Backups run automatically: on start, every N hours, and on close — to a local folder and,
   when available, to the Google Drive for desktop folder, which uploads them to the cloud. */
const { app, BrowserWindow, ipcMain, dialog, shell, Menu, net } = require("electron");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

/* This file holds the whole desktop program. It is started by main.cjs, which picks the newest
   downloaded version of this file (automatic program updates) or the one that came with the installer. */
const BOOT = process.shahinBoot || { appDir: __dirname, coreDir: __dirname, coreVersion: app.getVersion(), coreRoot: path.join(app.getPath("appData"), "Shahin ERP", "core-updates") };
const APP_DIR = BOOT.appDir; // folder of the installed program (icon, built-in screens)

const exeDir = path.dirname(process.execPath);
const portableDir = process.env.PORTABLE_EXECUTABLE_DIR || (fs.existsSync(path.join(exeDir, "portable.txt")) ? exeDir : null);
/* the app folder ("App") sits next to the data folder, so data stays put when the program is replaced */
function pickDataDir() {
  if (!portableDir) return path.join(app.getPath("documents"), "Shahin ERP");
  const own = path.join(portableDir, "ShahinERP-Data");
  const beside = path.join(portableDir, "..", "ShahinERP-Data");
  if (!fs.existsSync(own) && fs.existsSync(beside)) return beside;
  if (!fs.existsSync(own) && path.basename(portableDir).toLowerCase() === "app") return beside;
  return own;
}
/* Finding the company data — it must never "disappear" because the program was installed in a new place.
   1. data next to the program (USB / portable) is used when it exists;
   2. a folder that was combined into another one carries moved-to.json pointing to the new place;
   3. otherwise the last folder used (remembered outside the program) or any known Shahin ERP data
      folder on this computer is found, and the newest one is used. When the program sits in the
      user's own folders, that data is copied next to it (the old folder stays as a backup). */
const memoryFile = path.join(app.getPath("appData"), "Shahin ERP", "data-location.json");
const DATA = "shahin-erp-data.json";
const hasData = (d) => {
  try {
    return fs.statSync(path.join(d, DATA)).size > 2;
  } catch {
    return false;
  }
};
function follow(d, depth = 0) {
  try {
    const m = JSON.parse(fs.readFileSync(path.join(d, "moved-to.json"), "utf8"));
    if (depth < 5 && m.dataDir && path.resolve(m.dataDir) !== path.resolve(d) && hasData(m.dataDir)) return follow(m.dataDir, depth + 1);
  } catch {}
  return d;
}
function rememberedDir() {
  try {
    const d = JSON.parse(fs.readFileSync(memoryFile, "utf8")).dataDir;
    return d && hasData(d) ? follow(d) : null;
  } catch {
    return null;
  }
}
function knownDirs() {
  const home = app.getPath("home");
  const safe = (n) => {
    try {
      return app.getPath(n);
    } catch {
      return null;
    }
  };
  const bases = [safe("downloads"), safe("desktop"), safe("documents"), home, path.join(home, "Downloads"), path.join(home, "Desktop")].filter(Boolean);
  const out = [path.join(safe("documents") || home, "Shahin ERP")];
  bases.forEach((b) => out.push(path.join(b, "ShahinERP-Data"), path.join(b, "Shahin ERP", "ShahinERP-Data")));
  return [...new Set(out)];
}
function newestKnown() {
  const found = [rememberedDir(), ...knownDirs().map((d) => (hasData(d) ? follow(d) : null))].filter(Boolean);
  found.sort((a, b) => fs.statSync(path.join(b, DATA)).mtimeMs - fs.statSync(path.join(a, DATA)).mtimeMs);
  return found[0] || null;
}
function chooseDataDir() {
  const picked = pickDataDir();
  if (hasData(picked)) return follow(picked);
  const found = newestKnown();
  if (!found) return picked;
  const insideHome = path.resolve(picked).toLowerCase().startsWith(path.resolve(app.getPath("home")).toLowerCase());
  if (portableDir && insideHome) {
    try {
      fs.mkdirSync(picked, { recursive: true });
      fs.cpSync(found, picked, { recursive: true, filter: (src) => !src.includes("app-updates") });
      if (hasData(picked)) {
        fs.writeFileSync(path.join(found, "moved-to.json"), JSON.stringify({ dataDir: picked, at: new Date().toISOString(), note: "Shahin ERP now keeps its data in dataDir. This folder is an older copy kept as a backup." }, null, 2));
        return picked;
      }
    } catch {}
  }
  return found;
}
const dataDir = chooseDataDir();
try {
  fs.mkdirSync(path.dirname(memoryFile), { recursive: true });
  fs.writeFileSync(memoryFile, JSON.stringify({ dataDir, at: new Date().toISOString() }));
} catch {}
const dataFile = path.join(dataDir, "shahin-erp-data.json");
const configFile = path.join(dataDir, "settings.json");
const localBackupDir = path.join(dataDir, "Backups");
const reportsDir = path.join(dataDir, "Reports");
const dailyDir = path.join(localBackupDir, "Daily");
const safetyDir = path.join(localBackupDir, "Safety");
[dataDir, localBackupDir, reportsDir, dailyDir, safetyDir].forEach((d) => fs.mkdirSync(d, { recursive: true }));

let cfg = { googleDir: null, everyHours: 1, keep: 200, lastBackup: null, lastBackupError: null };
try {
  cfg = { ...cfg, ...JSON.parse(fs.readFileSync(configFile, "utf8")) };
} catch {}
// older versions kept fewer backups: raise the floor
cfg.keep = Math.max(200, Number(cfg.keep) || 200);
cfg.everyHours = Math.min(Number(cfg.everyHours) || 1, 1);
const saveCfg = () => fs.writeFileSync(configFile, JSON.stringify(cfg, null, 2));

/* ---------- merge-in: records from another copy of the data are added, never replacing newer ones ----------
   Any .json data file placed in ShahinERP-Data\merge-in is combined into the company data at start:
   records are matched by id and the newer version (updated_at) is kept; nothing is deleted.
   The file is then moved to Backups\Merged. */
function mergeIncoming() {
  const inDir = path.join(dataDir, "merge-in");
  if (!fs.existsSync(inDir)) return;
  const files = fs.readdirSync(inDir).filter((f) => f.endsWith(".json"));
  if (!files.length) return;
  let base = {};
  try {
    base = fs.existsSync(dataFile) ? JSON.parse(fs.readFileSync(dataFile, "utf8")) : {};
  } catch {
    return; // never merge into a damaged file
  }
  const doneDir = path.join(localBackupDir, "Merged");
  fs.mkdirSync(doneDir, { recursive: true });
  try {
    if (fs.existsSync(dataFile)) fs.copyFileSync(dataFile, path.join(safetyDir, `shahin-erp-backup-${stamp()}-before-merge.json`));
  } catch {}
  for (const f of files) {
    try {
      const add = JSON.parse(fs.readFileSync(path.join(inDir, f), "utf8"));
      for (const [t, rows] of Object.entries(add)) {
        if (!Array.isArray(rows)) continue;
        const cur = Array.isArray(base[t]) ? base[t] : [];
        const byId = new Map(cur.map((r) => [r && r.id, r]));
        for (const r of rows) {
          if (!r || !r.id) continue;
          const have = byId.get(r.id);
          if (!have) byId.set(r.id, r);
          else if (String(r.updated_at || "") > String(have.updated_at || "")) byId.set(r.id, { ...have, ...r });
        }
        base[t] = [...byId.values()].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
      }
      fs.renameSync(path.join(inDir, f), path.join(doneDir, `${stamp()}-${f}`));
    } catch {}
  }
  const tmp = dataFile + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(base));
  fs.renameSync(tmp, dataFile);
}

/* ---------- data file: protected so saved data is never lost ----------
   - every write is atomic (a power cut never leaves a half-written file)
   - a damaged file is never overwritten: it is set aside and the newest good backup is used
   - before any save that removes records, the previous file is copied to Backups\Safety
   - if anything else changed the file since this window loaded it, that version is kept in Backups\Safety too */
let pending = null;
let timer = null;
let knownMtime = 0;
const countRows = (o) => Object.values(o || {}).reduce((n, v) => n + (Array.isArray(v) ? v.length : 0), 0);
function safetyCopy(text, why) {
  try {
    fs.writeFileSync(path.join(safetyDir, `shahin-erp-backup-${stamp()}-${why}.json`), text);
    const files = fs.readdirSync(safetyDir).filter((f) => f.endsWith(".json")).sort();
    while (files.length > 300) fs.unlinkSync(path.join(safetyDir, files.shift()));
  } catch {}
}
function readGood(file) {
  try {
    const t = fs.readFileSync(file, "utf8");
    const o = JSON.parse(t);
    return o && typeof o === "object" ? { text: t, obj: o } : null;
  } catch {
    return null;
  }
}
function newestGoodBackup() {
  const dirs = [localBackupDir, dailyDir, safetyDir];
  const all = [];
  dirs.forEach((d) => {
    try {
      fs.readdirSync(d).filter((f) => f.endsWith(".json")).forEach((f) => all.push(path.join(d, f)));
    } catch {}
  });
  all.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
  for (const f of all) {
    const g = readGood(f);
    if (g && countRows(g.obj) > 0) return g;
  }
  return null;
}
function writeNow() {
  if (pending === null) return;
  try {
    if (fs.existsSync(dataFile)) {
      const st = fs.statSync(dataFile);
      const disk = readGood(dataFile);
      if (disk) {
        const changedElsewhere = knownMtime && Math.abs(st.mtimeMs - knownMtime) > 1;
        let fewer = false;
        try {
          fewer = countRows(JSON.parse(pending)) < countRows(disk.obj);
        } catch {}
        if (changedElsewhere) safetyCopy(disk.text, "changed-elsewhere");
        else if (fewer) safetyCopy(disk.text, "before-removal");
      }
    }
    const tmp = dataFile + ".tmp";
    fs.writeFileSync(tmp, pending);
    fs.renameSync(tmp, dataFile);
    knownMtime = fs.statSync(dataFile).mtimeMs;
    pending = null;
    dailyBackup();
  } catch (err) {
    cfg.lastBackupError = "Could not save: " + String(err.message || err);
  }
}
ipcMain.on("data:load", (e) => {
  try {
    if (!fs.existsSync(dataFile)) {
      e.returnValue = null;
      return;
    }
    const good = readGood(dataFile);
    if (good) {
      knownMtime = fs.statSync(dataFile).mtimeMs;
      e.returnValue = good.text;
      return;
    }
    // damaged file: keep it aside, use the newest good backup
    try {
      fs.renameSync(dataFile, path.join(safetyDir, `damaged-${stamp()}.json`));
    } catch {}
    const b = newestGoodBackup();
    if (b) {
      fs.writeFileSync(dataFile, b.text);
      knownMtime = fs.statSync(dataFile).mtimeMs;
    }
    e.returnValue = b ? b.text : null;
  } catch {
    e.returnValue = null;
  }
});
ipcMain.on("data:save", (_e, json) => {
  pending = json;
  clearTimeout(timer);
  timer = setTimeout(writeNow, 400);
});

/* one copy per day that is never deleted */
function dailyBackup() {
  try {
    const d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    const f = path.join(dailyDir, `shahin-erp-daily-${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}.json`);
    fs.copyFileSync(dataFile, f);
  } catch {}
}

/* ---------- Google Drive for desktop detection ---------- */
function detectGoogle() {
  const home = app.getPath("home");
  const candidates = [path.join(home, "Google Drive", "My Drive"), path.join(home, "My Drive"), path.join(home, "Google Drive")];
  for (const l of "DEFGHIJKLMNOPQRSTUVWXYZ") candidates.push(`${l}:\\My Drive`, `${l}:\\Mi unidad`, `${l}:\\Meine Ablage`);
  return candidates.find((p) => {
    try {
      return fs.statSync(p).isDirectory();
    } catch {
      return false;
    }
  }) || null;
}

/* ---------- backups ---------- */
function stamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}
function prune(dir) {
  const files = fs.readdirSync(dir).filter((f) => /^shahin-erp-backup-.*\.json$/.test(f)).sort();
  while (files.length > cfg.keep) fs.unlinkSync(path.join(dir, files.shift()));
}
function backup(reason = "auto") {
  writeNow();
  if (!fs.existsSync(dataFile)) return { ok: false, files: [], error: "Nothing to back up yet" };
  const name = `shahin-erp-backup-${stamp()}${reason && reason !== "scheduled" && reason !== "auto" ? "-" + reason : ""}.json`;
  const files = [];
  try {
    fs.copyFileSync(dataFile, path.join(localBackupDir, name));
    files.push(path.join(localBackupDir, name));
    prune(localBackupDir);
    if (cfg.googleDir) {
      const g = path.join(cfg.googleDir, "Shahin ERP Backups");
      fs.mkdirSync(g, { recursive: true });
      fs.copyFileSync(dataFile, path.join(g, name));
      files.push(path.join(g, name));
      prune(g);
    }
    cfg.lastBackup = new Date().toISOString();
    cfg.lastBackupError = null;
    saveCfg();
    return { ok: true, files, reason };
  } catch (err) {
    cfg.lastBackupError = String(err.message || err);
    saveCfg();
    return { ok: false, files, error: cfg.lastBackupError };
  }
}
let backupTimer = null;
function schedule() {
  clearInterval(backupTimer);
  backupTimer = setInterval(() => backup("scheduled"), Math.max(1, Number(cfg.everyHours) || 2) * 3600 * 1000);
}

function listBackups() {
  const out = [];
  const add = (dir, location) => {
    try {
      fs.readdirSync(dir)
        .filter((f) => /^shahin-erp-(backup|daily)-.*\.json$/.test(f))
        .forEach((f) => {
          const st = fs.statSync(path.join(dir, f));
          out.push({ name: f, path: path.join(dir, f), size: st.size, at: st.mtime.toISOString(), location });
        });
    } catch {}
  };
  add(localBackupDir, "local");
  add(safetyDir, "local");
  add(dailyDir, "local");
  if (cfg.googleDir) add(path.join(cfg.googleDir, "Shahin ERP Backups"), "google");
  return out.sort((a, b) => b.at.localeCompare(a.at));
}

ipcMain.handle("app:info", () => ({
  version: installedUpdate()?.version || app.getVersion(),
  program: BOOT.coreVersion,
  portable: !!portableDir,
  dataFile,
  localBackupDir,
  googleBackupDir: cfg.googleDir ? path.join(cfg.googleDir, "Shahin ERP Backups") : null,
  googleDetected: detectGoogle(),
  lastBackup: cfg.lastBackup,
  lastBackupError: cfg.lastBackupError,
}));
ipcMain.handle("backup:now", () => backup("manual"));
ipcMain.handle("backup:list", () => listBackups());
ipcMain.handle("backup:restore", (_e, file) => {
  try {
    const text = fs.readFileSync(file, "utf8");
    JSON.parse(text);
    backup("before-restore");
    pending = text;
    writeNow();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: "That backup file could not be read" };
  }
});
ipcMain.handle("backup:google-detect", () => {
  const g = detectGoogle();
  if (g) {
    cfg.googleDir = g;
    saveCfg();
    backup("google-connected");
  }
  return g;
});
ipcMain.handle("backup:google-choose", async () => {
  const r = await dialog.showOpenDialog({ title: "Choose a folder that syncs to the cloud", properties: ["openDirectory", "createDirectory"] });
  if (r.canceled || !r.filePaths[0]) return null;
  cfg.googleDir = r.filePaths[0];
  saveCfg();
  backup("folder-chosen");
  return cfg.googleDir;
});
ipcMain.handle("backup:configure", (_e, c) => {
  cfg.everyHours = Math.min(Number(c.everyHours) || 1, 1);
  cfg.keep = Math.max(200, Number(c.keep) || 200);
  saveCfg();
  schedule();
});
ipcMain.handle("shell:open-folder", (_e, p) => shell.openPath(p));
ipcMain.handle("shell:open-external", (_e, url) => {
  if (/^(https?:|mailto:)/i.test(url)) return shell.openExternal(url);
});
ipcMain.handle("shell:show-item", (_e, p) => shell.showItemInFolder(p));
/* one-click printing: straight to the default printer when "direct print" is on, otherwise the print dialog */
ipcMain.handle("print:page", (e, opts = {}) =>
  new Promise((resolve) => {
    const wc = e.sender;
    wc.print({ silent: !!opts.silent, printBackground: true, copies: Math.max(1, Number(opts.copies) || 1), deviceName: opts.deviceName || undefined }, (ok, reason) => resolve({ ok, reason: ok ? null : reason }));
  }),
);
/* "email copy": the page as it looks on screen, saved as an A4 PDF in the Reports folder */
ipcMain.handle("print:pdf", async (e, filename) => {
  const safe = String(filename || "document.pdf").replace(/[\\/:*?"<>|]+/g, "-");
  const file = path.join(reportsDir, safe.endsWith(".pdf") ? safe : safe + ".pdf");
  const data = await e.sender.printToPDF({ printBackground: true, pageSize: "A4", margins: { marginType: "custom", top: 0.55, bottom: 0.55, left: 0.55, right: 0.55 } });
  fs.writeFileSync(file, data);
  return file;
});
ipcMain.handle("print:printers", async (e) => (await e.sender.getPrintersAsync()).map((p) => ({ name: p.name, displayName: p.displayName || p.name, isDefault: !!p.isDefault })));
/* online computers keep an hourly copy of the online data here as well (Backups/Online, 7 days) */
ipcMain.handle("mirror:save", (_e, json) => {
  try {
    const dir = path.join(localBackupDir, "Online");
    fs.mkdirSync(dir, { recursive: true });
    JSON.parse(json);
    fs.writeFileSync(path.join(dir, `shahin-erp-online-${stamp()}.json`), json);
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
    while (files.length > 24 * 7) fs.unlinkSync(path.join(dir, files.shift()));
    if (cfg.googleDir) {
      const g = path.join(cfg.googleDir, "Shahin ERP Backups");
      fs.mkdirSync(g, { recursive: true });
      fs.writeFileSync(path.join(g, "shahin-erp-online-latest.json"), json);
    }
    return true;
  } catch {
    return false;
  }
});
ipcMain.handle("pdf:save", (_e, filename, base64) => {
  const safe = String(filename).replace(/[\\/:*?"<>|]+/g, "-");
  const file = path.join(reportsDir, safe);
  fs.writeFileSync(file, Buffer.from(base64, "base64"));
  return file;
});


/* ---------- automatic updates ----------
   The program checks the update channel on start and every 6 hours. A newer version of the app
   screens is downloaded, its SHA-256 checksum verified, and used from the next start (or at once
   when the user presses "Restart now"). Company data is never touched by an update. If an updated
   version fails to load, the app falls back to the built-in version. */
const UPDATE_BASE = process.env.SHAHIN_UPDATE_URL || "https://raw.githubusercontent.com/farhanmalikhost-coder/shahin-erp-updates/main/";
const updatesDir = BOOT.coreRoot;
fs.mkdirSync(updatesDir, { recursive: true });
const builtInVersion = app.getVersion();
const runningCore = BOOT.coreVersion || builtInVersion;
const cmp = (a, b) => {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
};
function installedUpdate() {
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(updatesDir, "current.json"), "utf8"));
    const file = path.join(updatesDir, meta.version, "index.html");
    if (cmp(meta.version, builtInVersion) > 0 && fs.existsSync(file) && meta.version !== cfg.badVersion && !fs.existsSync(path.join(updatesDir, "bad-" + meta.version))) return { version: meta.version, file };
  } catch {}
  return null;
}
let updateState = { status: "idle", current: builtInVersion, available: null, notes: "", error: null };
async function checkForUpdate(manual = false) {
  try {
    updateState.status = "checking";
    const res = await net.fetch(UPDATE_BASE + "latest.json?t=" + Date.now(), { cache: "no-store" });
    if (!res.ok) throw new Error("Update server returned " + res.status);
    const latest = await res.json();
    const running = installedUpdate()?.version || builtInVersion;
    updateState.current = running;
    if (cmp(latest.version, running) <= 0 || latest.version === cfg.badVersion) {
      updateState = { ...updateState, status: "latest", available: null, error: null };
      return updateState;
    }
    if (latest.minDesktop && cmp(builtInVersion, latest.minDesktop) < 0) {
      updateState = { ...updateState, status: "needs-new-program", available: latest.version, notes: latest.notes || "", error: null };
      return updateState;
    }
    updateState.status = "downloading";
    BrowserWindow.getAllWindows().forEach((w) => w.webContents.send("update:ready", updateState));
    const get = async (file, sha256) => {
      const r = await net.fetch(UPDATE_BASE + file + "?t=" + Date.now(), { cache: "no-store" });
      if (!r.ok) throw new Error("Download failed (" + r.status + ")");
      const b = Buffer.from(await r.arrayBuffer());
      if (crypto.createHash("sha256").update(b).digest("hex") !== sha256) throw new Error("Downloaded file failed the safety check");
      return b;
    };
    // screens, program and bridge are all downloaded and checked before anything is switched
    const buf = await get(latest.file, latest.sha256);
    const core = latest.core ? await get(latest.core.file, latest.core.sha256) : null;
    const preload = latest.preload ? await get(latest.preload.file, latest.preload.sha256) : null;
    const dir = path.join(updatesDir, latest.version);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "index.html"), buf);
    if (core) fs.writeFileSync(path.join(dir, "core.cjs"), core);
    if (preload) fs.writeFileSync(path.join(dir, "preload.cjs"), preload);
    const sha = latest.sha256;
    fs.writeFileSync(path.join(updatesDir, "current.json"), JSON.stringify({ version: latest.version, sha256: sha, program: !!core, at: new Date().toISOString() }));
    // keep only the two newest downloaded versions
    fs.readdirSync(updatesDir)
      .filter((d) => /^\d+\.\d+\.\d+$/.test(d))
      .sort(cmp)
      .slice(0, -2)
      .forEach((d) => fs.rmSync(path.join(updatesDir, d), { recursive: true, force: true }));
    updateState = { ...updateState, status: "ready", available: latest.version, notes: latest.notes || "", error: null };
    BrowserWindow.getAllWindows().forEach((w) => w.webContents.send("update:ready", updateState));
    return updateState;
  } catch (err) {
    updateState = { ...updateState, status: manual ? "error" : "idle", error: String(err.message || err) };
    return updateState;
  }
}
ipcMain.handle("update:check", () => checkForUpdate(true));
ipcMain.handle("update:state", () => ({ ...updateState, current: installedUpdate()?.version || builtInVersion }));
ipcMain.handle("update:restart", () => {
  writeNow();
  backup("before-update");
  app.relaunch();
  app.exit(0);
});

/* ---------- window ---------- */
function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 380,
    title: "Shahin ERP",
    backgroundColor: "#f5f7fb",
    icon: path.join(APP_DIR, "icon.png"),
    webPreferences: {
      preload: fs.existsSync(path.join(BOOT.coreDir, "preload.cjs")) ? path.join(BOOT.coreDir, "preload.cjs") : path.join(APP_DIR, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  const builtIn = path.join(APP_DIR, "..", "dist-desktop", "index.html");
  // the program version that started fine is marked healthy, so it is kept
  win.webContents.once("did-finish-load", () => {
    try {
      if (BOOT.coreVersion) fs.writeFileSync(path.join(updatesDir, "healthy-" + BOOT.coreVersion), new Date().toISOString());
    } catch {}
  });
  const upd = installedUpdate();
  win.loadFile(upd ? upd.file : builtIn);
  if (upd) {
    // an update that cannot load is set aside and the built-in version is used
    const fallback = () => {
      cfg.badVersion = upd.version;
      saveCfg();
      try {
        fs.writeFileSync(path.join(updatesDir, "bad-" + upd.version), "failed to load");
      } catch {}
      win.loadFile(builtIn);
    };
    win.webContents.once("did-fail-load", fallback);
    win.webContents.once("render-process-gone", fallback);
  }
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^(https?:|mailto:)/i.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
}

Menu.setApplicationMenu(null);
/* one copy only: a second double-click brings the open window to the front instead of starting again */
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    const w = BrowserWindow.getAllWindows()[0];
    if (w) {
      if (w.isMinimized()) w.restore();
      w.show();
      w.focus();
    }
  });
}
app.whenReady().then(() => {
  try {
    mergeIncoming();
  } catch {}
  createWindow();
  backup("startup");
  schedule();
  setTimeout(() => checkForUpdate(false), 15000);
  setInterval(() => checkForUpdate(false), 2 * 3600 * 1000);
});
app.on("before-quit", () => {
  writeNow();
  backup("on-close");
});
app.on("window-all-closed", () => app.quit());
