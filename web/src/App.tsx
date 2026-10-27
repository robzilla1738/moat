import { useEffect, useId, useState, type ReactNode } from "react";
import { Button, Details, EmptyState, Icon, type IconName } from "./components/ui";
import { useStore } from "./data/store";
import { snapshotAgeMs, SNAPSHOT_STALE_AFTER_MS } from "./data/freshness";
import { ago } from "./format";
import { SignIn } from "./screens/SignIn";
import { Overview } from "./screens/Overview";
import { Activity, IncidentDetail } from "./screens/Activity";
import { SessionDetail, Sessions } from "./screens/Sessions";
import { Rules } from "./screens/Rules";
import { DeviceDetail, Devices } from "./screens/Devices";
import { AppDetail, AppsHome, Diagnostics, WhatChanged } from "./screens/Standalone";
import { CoverageScreen } from "./screens/Coverage";
import { BaselineView, CandidateReview, Learning, Packs } from "./screens/Learning";

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

/**
 * Primary navigation. Six views on a desktop, five on a phone (Overview is one tap from the Apps status line).
 * Learn and rule packs live under Rules; coverage, recovery and "What changed?" live under Devices.
 */
const NAV: { key: string; label: string; icon: IconName; mobile: boolean; also: string[] }[] = [
  { key: "", label: "Apps", icon: "apps", mobile: true, also: ["apps"] },
  { key: "overview", label: "Overview", icon: "grid", mobile: false, also: [] },
  { key: "activity", label: "Activity", icon: "activity", mobile: true, also: ["r"] },
  { key: "sessions", label: "Tasks", icon: "sessions", mobile: true, also: [] },
  { key: "rules", label: "Rules", icon: "rules", mobile: true, also: ["learning"] },
  { key: "devices", label: "Devices", icon: "devices", mobile: true, also: ["coverage", "diagnostics", "changed"] },
];
const isActive = (section: string, n: (typeof NAV)[number], mobile: boolean) => section === n.key || n.also.includes(section) || (mobile && n.key === "devices" && section === "overview");
/** A one-computer user does not land in fleet administration: "Devices" reads "This computer". */
const navLabel = (key: string, label: string, deviceCount: number) => (key === "devices" && deviceCount === 1 ? "This computer" : label);
/** The phone tab bar has room for one word per tab: "Computer" there, "This computer" everywhere else. */
const tabLabel = (key: string, label: string, deviceCount: number) => (key === "devices" && deviceCount === 1 ? "Computer" : label);

/**
 * Appearance follows the system (prefers-color-scheme, live) until the owner picks one with the toggle; that choice
 * persists in localStorage ("moat.theme") and wins from then on.
 */
function useTheme(): [string, () => void] {
  const system = () => (typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const [chosen, setChosen] = useState<string | null>(() => (typeof window === "undefined" ? null : localStorage.getItem("moat.theme")));
  const [sys, setSys] = useState(system);
  useEffect(() => {
    const m = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!m) return;
    const on = () => setSys(system());
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  const theme = chosen === "light" || chosen === "dark" ? chosen : sys;
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.setAttribute("content", theme === "light" ? "#FFFFFF" : "#151821"));
  }, [theme]);
  return [
    theme,
    () => {
      const next = theme === "light" ? "dark" : "light";
      localStorage.setItem("moat.theme", next);
      setChosen(next);
    },
  ];
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
        <EmptyState title="Notification not found" icon="alert" action={<Button onClick={() => go("activity")}>Open Activity</Button>}>
          {err}
        </EmptyState>
      ) : (
        <div className="muted small" role="status">
          Opening the notification…
        </div>
      )}
    </div>
  );
}

/** Mode and freshness are visible on every screen, as a banner that is never collapsed. */
function StatusBanner() {
  const { mode, demoOnly, status, error, data, signOut, refresh } = useStore();
  const [, tick] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => tick((n) => n + 1), 15_000);
    return () => window.clearInterval(t);
  }, []);
  if (mode === "demo")
    return (
      <div className="banner tone-blue banner-global" role="status">
        <span className="banner-icon" aria-hidden>
          <Icon name="info" size={16} />
        </span>
        <div className="banner-body">
          <strong className="banner-title">Sample data.</strong> <span className="banner-text">Nothing here is about your devices, and buttons don&apos;t send anything.</span>
        </div>
        {!demoOnly && (
          <button type="button" className="link-btn" onClick={signOut}>
            Leave sample data
          </button>
        )}
      </div>
    );
  if (!data) return null;
  const age = snapshotAgeMs(data);
  if (status === "unreachable" || status === "unauthorized" || age > SNAPSHOT_STALE_AFTER_MS)
    return (
      <div className="banner tone-amber banner-global" role="alert">
        <span className="banner-icon" aria-hidden>
          <Icon name="alert" size={16} />
        </span>
        <div className="banner-body">
          <strong className="banner-title">{status === "unauthorized" ? "Signed out by the controller." : "Not current."}</strong>{" "}
          <span className="banner-text">
            {status === "unauthorized" ? "Your controller no longer accepts this sign-in." : status === "unreachable" ? "Moat can't reach your controller." : "Updates stopped."} Showing what it reported {ago(data.fetchedAt)}; actions are paused.
          </span>
          {error && (
            <Details summary="Technical details">
              <span className="mono">{error}</span>
            </Details>
          )}
        </div>
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
              <h1 className="signin-title">Can&apos;t reach the controller</h1>
              <p className="lede">Nothing is shown rather than old or sample data. Your devices keep protecting themselves without this page.</p>
              {store.error && (
                <Details summary="Technical details">
                  <span className="mono">{store.error}</span>
                </Details>
              )}
              <div className="actions">
                <Button kind="primary" onClick={() => void store.refresh()}>
                  Try again
                </Button>
                <Button kind="quiet" onClick={store.signOut}>
                  Sign out
                </Button>
              </div>
            </>
          ) : (
            <div className="muted" role="status">
              Loading from your controller…
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
    case "learning":
      screen = parts[1] === "packs" ? <Packs /> : parts[1] === "c" && parts[2] ? <CandidateReview id={decodeURIComponent(parts[2])} go={go} /> : parts[1] === "b" && parts[2] ? <BaselineView id={decodeURIComponent(parts[2])} go={go} /> : <Learning go={go} />;
      break;
    case "devices":
      screen = parts[1] ? <DeviceDetail id={decodeURIComponent(parts[1])} go={go} /> : <Devices go={go} />;
      break;
    case "apps":
      screen = parts[1] ? <AppDetail id={decodeURIComponent(parts[1])} go={go} /> : <AppsHome go={go} />;
      break;
    case "changed":
      screen = <WhatChanged go={go} />;
      break;
    case "diagnostics":
      screen = <Diagnostics />;
      break;
    case "overview":
      screen = <Overview go={go} />;
      break;
    case "coverage":
      screen = <CoverageScreen go={go} />;
      break;
    default:
      screen = <AppsHome go={go} />;
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
            <a key={n.key} href={`#/${n.key}`} className={`side-link ${isActive(section, n, false) ? "active" : ""}`} aria-current={isActive(section, n, false) ? "page" : undefined}>
              <Icon name={n.icon} />
              <span>{navLabel(n.key, n.label, data.devices.length)}</span>
              {n.key === "activity" && open > 0 && <span className="count">{open}</span>}
            </a>
          ))}
        </nav>
        <div className="side-foot">
          <div className="side-who">
            <span>{mode === "demo" ? "Sample data" : data.viewer?.name ?? "Signed in"}</span>
            <span className="muted">{mode === "demo" ? "nothing is sent" : data.viewer?.role === "owner" ? "owner" : "read only"}</span>
          </div>
          <button type="button" className="icon-btn" onClick={toggle} aria-label={theme === "light" ? "Switch to dark appearance" : "Switch to light appearance"} aria-pressed={theme === "dark"}>
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
            {mode === "demo" && <span className="chip tone-blue">Sample</span>}
            {mode === "live" && (
              <button type="button" className="link-btn small" onClick={signOut}>
                Sign out
              </button>
            )}
            <button type="button" className="icon-btn" onClick={toggle} aria-label={theme === "light" ? "Switch to dark appearance" : "Switch to light appearance"} aria-pressed={theme === "dark"}>
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
          <a key={n.key} href={`#/${n.key}`} className={`tab ${isActive(section, n, true) ? "active" : ""}`} aria-current={isActive(section, n, true) ? "page" : undefined}>
            <span className="tab-icon">
              <Icon name={n.icon} size={21} />
              {n.key === "activity" && open > 0 && <span className="tab-badge">{open}</span>}
            </span>
            <span className="tab-label">{tabLabel(n.key, n.label, data.devices.length)}</span>
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

/** The Moat mark: a keep inside a moat ring that opens only below the gate (brand/moat-mark.svg). */
export function Logo({ size = 28 }: { size?: number }) {
  const gid = `lg-${useId().replace(/:/g, "")}`;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden className="logo">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset=".45" stopColor="var(--accent)" />
          <stop offset="1" stopColor="var(--teal)" />
        </linearGradient>
      </defs>
      <path fill={`url(#${gid})`} d="M10.55 20.73A8.85 8.85 0 1 1 13.45 20.73V22.65A10.75 10.75 0 1 0 10.55 22.65Z" />
      <path fill="var(--accent)" fillRule="evenodd" d="M7.2 5.6h2.2v1.7h1.5V5.6h2.2v1.7h1.5V5.6h2.2V18H7.2Zm3.35 12.4v-3.6a1.45 1.45 0 0 1 2.9 0V18Z" />
    </svg>
  );
}
