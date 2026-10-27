import { useEffect, useId, useState, type ReactNode } from "react";
import { Icon, type IconName } from "./components/ui";
import { useStore } from "./data/store";
import { snapshotAgeMs, SNAPSHOT_STALE_AFTER_MS } from "./data/freshness";
import { ago } from "./format";
import { SignIn } from "./screens/SignIn";
import { Home } from "./screens/Home";
import { Activity, IncidentDetail } from "./screens/Activity";
import { SessionDetail, Sessions } from "./screens/Sessions";
import { Rules } from "./screens/Rules";
import { DeviceDetail, Devices } from "./screens/Devices";
import { Apps } from "./screens/Apps";
import { CoverageScreen } from "./screens/Coverage";

export function useRoute(): [string[], (to: string) => void] {
  const parse = () => (typeof window === "undefined" ? "" : window.location.hash.replace(/^#\/?/, "") || "").split("/").filter(Boolean);
  const [parts, setParts] = useState(parse);
  useEffect(() => {
    const on = () => {
      setParts(parse());
      window.scrollTo({ top: 0 });
    };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return [parts, (to: string) => (window.location.hash = `#/${to}`)];
}

const NAV: { key: string; label: string; icon: IconName; mobile: boolean }[] = [
  { key: "", label: "Home", icon: "home", mobile: true },
  { key: "activity", label: "Activity", icon: "activity", mobile: true },
  { key: "sessions", label: "Sessions", icon: "sessions", mobile: true },
  { key: "rules", label: "Rules", icon: "rules", mobile: true },
  { key: "devices", label: "Devices", icon: "devices", mobile: true },
  { key: "apps", label: "Apps", icon: "apps", mobile: false },
  { key: "coverage", label: "Coverage", icon: "coverage", mobile: false },
];

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => (typeof window === "undefined" ? "dark" : localStorage.getItem("moat.theme") ?? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")));
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("moat.theme", theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "light" ? "#f6f7f9" : "#0a0b0d");
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "light" ? "dark" : "light"))];
}

/** `#/r/<ref>`: an opaque notification reference resolves to exactly one incident, or to nothing. */
function RefRoute({ refId, go }: { refId: string; go: (to: string) => void }) {
  const { resolveRef } = useStore();
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    void resolveRef(refId).then((r) => {
      if (!live) return;
      if ("incidentId" in r) window.location.replace(`#/activity/${encodeURIComponent(r.incidentId)}`);
      else setErr(r.error);
    });
    return () => {
      live = false;
    };
  }, [refId, resolveRef]);
  return (
    <div className="page">
      {err ? (
        <div className="empty">
          <div className="empty-title">Notification not found</div>
          <div className="muted small">{err}</div>
          <button type="button" className="btn btn-quiet" onClick={() => go("activity")}>
            Open Activity
          </button>
        </div>
      ) : (
        <div className="muted small" role="status">
          Opening the notification…
        </div>
      )}
    </div>
  );
}

/** Mode and freshness are visible on every screen. */
function StatusBanner() {
  const { mode, demoOnly, status, error, data, signOut, refresh } = useStore();
  const [, tick] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => tick((n) => n + 1), 15_000);
    return () => window.clearInterval(t);
  }, []);
  if (mode === "demo")
    return (
      <div className="mode-banner mode-demo" role="status">
        <strong>Sample data.</strong> Nothing here describes your devices, and actions send nothing.
        {!demoOnly && (
          <button type="button" className="link-btn" onClick={signOut}>
            Leave demo
          </button>
        )}
      </div>
    );
  if (!data) return null;
  const age = snapshotAgeMs(data);
  if (status === "unreachable" || status === "unauthorized" || age > SNAPSHOT_STALE_AFTER_MS)
    return (
      <div className="mode-banner mode-stale" role="alert">
        <strong>{status === "unauthorized" ? "Signed out by the controller." : "Not current."}</strong> {error ?? "Updates stopped."} Showing what the controller reported {ago(data.fetchedAt)}; actions are paused.
        <button type="button" className="link-btn" onClick={() => void refresh()}>
          Retry
        </button>
      </div>
    );
  return null;
}

export function App() {
  const store = useStore();
  if (store.mode === "live" && store.status === "signed_out") return <SignIn />;
  if (store.mode === "live" && store.status === "unauthorized" && !store.data) return <SignIn />;
  if (!store.data)
    return (
      <div className="signin">
        <div className="signin-card card">
          {store.status === "unreachable" ? (
            <>
              <h1 className="signin-title">Can't reach the controller</h1>
              <p className="muted small">{store.error}</p>
              <p className="muted small">Nothing is shown rather than old or sample data. Enforcement on your devices does not depend on this page.</p>
              <div className="decision-actions">
                <button type="button" className="btn btn-primary" onClick={() => void store.refresh()}>
                  Retry
                </button>
                <button type="button" className="btn btn-quiet" onClick={store.signOut}>
                  Sign out
                </button>
              </div>
            </>
          ) : (
            <div className="muted small" role="status">
              Loading from the controller…
            </div>
          )}
        </div>
      </div>
    );
  return <Shell />;
}

function Shell() {
  const [parts, go] = useRoute();
  const [theme, toggle] = useTheme();
  const { toast, dismissToast, mode, signOut } = useStore();
  const data = useStore().data!;
  const section = parts[0] ?? "";
  const open = data.incidents.filter((i) => i.state === "open" && i.urgency !== "low").length;

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(dismissToast, 4200);
    return () => window.clearTimeout(t);
  }, [toast, dismissToast]);

  let screen: ReactNode;
  switch (section) {
    case "activity":
      screen = parts[1] ? <IncidentDetail id={decodeURIComponent(parts[1])} go={go} /> : <Activity go={go} />;
      break;
    case "r":
      screen = <RefRoute refId={decodeURIComponent(parts[1] ?? "")} go={go} />;
      break;
    case "sessions":
      screen = parts[1] ? <SessionDetail id={decodeURIComponent(parts[1])} go={go} /> : <Sessions go={go} />;
      break;
    case "rules":
      screen = <Rules go={go} />;
      break;
    case "devices":
      screen = parts[1] ? <DeviceDetail id={decodeURIComponent(parts[1])} go={go} /> : <Devices go={go} />;
      break;
    case "apps":
      screen = <Apps go={go} />;
      break;
    case "coverage":
      screen = <CoverageScreen go={go} />;
      break;
    default:
      screen = <Home go={go} />;
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#/">
          <Logo />
          <span>Moat</span>
        </a>
        <nav className="side-nav">
          {NAV.map((n) => (
            <a key={n.key} href={`#/${n.key}`} className={`side-link ${section === n.key || (section === "r" && n.key === "activity") ? "active" : ""}`}>
              <Icon name={n.icon} />
              <span>{n.label}</span>
              {n.key === "activity" && open > 0 && <span className="count">{open}</span>}
            </a>
          ))}
        </nav>
        <div className="side-foot">
          <div className="rev-chip">
            <span className="mono">rev {data.policyRevision}</span>
            <span className="muted">{mode === "demo" ? "sample data" : `live · ${data.viewer?.role ?? "?"}`}</span>
          </div>
          <button type="button" className="icon-btn" onClick={toggle} aria-label="Toggle theme">
            <Icon name={theme === "light" ? "moon" : "sun"} />
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <a className="brand brand-mobile" href="#/">
            <Logo />
            <span>Moat</span>
          </a>
          <div className="topbar-right">
            {mode === "demo" && <span className="demo-pill">Demo</span>}
            {mode === "live" && (
              <button type="button" className="link-btn small" onClick={signOut}>
                Sign out
              </button>
            )}
            <button type="button" className="icon-btn" onClick={toggle} aria-label="Toggle theme">
              <Icon name={theme === "light" ? "moon" : "sun"} />
            </button>
          </div>
        </header>
        <StatusBanner />
        <main className="content" key={parts.join("/")}>
          {screen}
        </main>
      </div>
      <nav className="tabbar" aria-label="Primary">
        {NAV.filter((n) => n.mobile).map((n) => (
          <a key={n.key} href={`#/${n.key}`} className={`tab ${section === n.key || (n.key === "devices" && (section === "apps" || section === "coverage")) || (n.key === "activity" && section === "r") ? "active" : ""}`}>
            <span className="tab-icon">
              <Icon name={n.icon} size={21} />
              {n.key === "activity" && open > 0 && <span className="tab-badge">{open}</span>}
            </span>
            <span>{n.label}</span>
          </a>
        ))}
      </nav>
      {toast && (
        <div className="toast" role="status" onClick={dismissToast}>
          <Icon name="check" size={16} />
          <span>{toast}</span>
        </div>
      )}
    </div>
  );
}

export function Logo() {
  const gid = `lg-${useId().replace(/:/g, "")}`;
  return (
    <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden className="logo">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--accent-2)" />
          <stop offset="1" stopColor="var(--accent)" />
        </linearGradient>
      </defs>
      <rect x="1" y="1" width="30" height="30" rx="9" fill={`url(#${gid})`} />
      <path d="M7 21.5c2.2 0 2.2-1.6 4.5-1.6s2.3 1.6 4.5 1.6 2.3-1.6 4.5-1.6 2.3 1.6 4.5 1.6" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" opacity=".95" />
      <path d="M10 17V10.5l2 1.2 2-1.2 2 1.2 2-1.2 2 1.2 2-1.2V17" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
