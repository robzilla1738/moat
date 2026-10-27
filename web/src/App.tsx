import { useEffect, useId, useState, type ReactNode } from "react";
import { Icon, type IconName } from "./components/ui";
import { useStore } from "./data/store";
import { Home } from "./screens/Home";
import { Activity, IncidentDetail } from "./screens/Activity";
import { SessionDetail, Sessions } from "./screens/Sessions";
import { Rules } from "./screens/Rules";
import { DeviceDetail, Devices } from "./screens/Devices";
import { Apps } from "./screens/Apps";
import { CoverageScreen } from "./screens/Coverage";

export function useRoute(): [string[], (to: string) => void] {
  const parse = () => (window.location.hash.replace(/^#\/?/, "") || "").split("/").filter(Boolean);
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
  const [theme, setTheme] = useState(() => localStorage.getItem("moat.theme") ?? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("moat.theme", theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "light" ? "#f6f7f9" : "#0a0b0d");
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "light" ? "dark" : "light"))];
}

export function App() {
  const [parts, go] = useRoute();
  const [theme, toggle] = useTheme();
  const { data, toast, dismissToast } = useStore();
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
      screen = parts[1] ? <IncidentDetail id={parts[1]} go={go} /> : <Activity go={go} />;
      break;
    case "r":
      screen = <IncidentDetail id={data.incidents[0]?.id ?? ""} go={go} />;
      break;
    case "sessions":
      screen = parts[1] ? <SessionDetail id={parts[1]} go={go} /> : <Sessions go={go} />;
      break;
    case "rules":
      screen = <Rules go={go} />;
      break;
    case "devices":
      screen = parts[1] ? <DeviceDetail id={parts[1]} go={go} /> : <Devices go={go} />;
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
            <span className="muted">{data.demo ? "demo data" : "live"}</span>
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
            {data.demo && <span className="demo-pill">Demo</span>}
            <button type="button" className="icon-btn" onClick={toggle} aria-label="Toggle theme">
              <Icon name={theme === "light" ? "moon" : "sun"} />
            </button>
          </div>
        </header>
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
