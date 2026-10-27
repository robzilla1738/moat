import { useState } from "react";
import { Card, Icon } from "../components/ui";
import { useStore } from "../data/store";
import { Logo } from "../App";

/** Live mode without a token. Demo data is only ever shown when chosen here, and it is labeled everywhere. */
export function SignIn() {
  const { signIn, enterDemo, status, error } = useStore();
  const [token, setToken] = useState("");
  return (
    <div className="signin">
      <Card className="signin-card">
        <div className="signin-brand">
          <Logo />
          <span>Moat</span>
        </div>
        <h1 className="signin-title">Sign in to your controller</h1>
        <p className="muted small">
          Paste a token from <span className="mono">moat-controller token owner</span> (or <span className="mono">viewer</span> for read only). It is kept in this browser's storage for this controller; it is not an owner signing key and cannot authorize broadening changes on its own.
        </p>
        {status === "unauthorized" && <div className="small bad">{error}</div>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (token.trim()) signIn(token.trim());
          }}
        >
          <label className="small" htmlFor="token">
            Access token
          </label>
          <input id="token" className="input mono" type="password" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} />
          <button type="submit" className="btn btn-primary signin-go" disabled={!token.trim()}>
            <Icon name="shield" size={16} /> Sign in
          </button>
        </form>
        <div className="signin-or muted small">or</div>
        <button type="button" className="btn btn-quiet" onClick={enterDemo}>
          Explore sample data
        </button>
        <p className="muted small">Sample data is a fixed demonstration. Nothing in it describes your devices, and its buttons send nothing.</p>
      </Card>
    </div>
  );
}
