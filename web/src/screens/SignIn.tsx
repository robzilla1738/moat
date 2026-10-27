import { useState } from "react";
import { Button, Card, Details, Fine } from "../components/ui";
import { useStore } from "../data/store";
import { Logo } from "../App";

/** Live mode without a token. Sample data is only ever shown when chosen here, and it is labelled everywhere. */
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
        <p className="lede">Moat watches what your apps connect to and blocks what you haven&apos;t allowed. Sign in to see your devices.</p>
        {status === "unauthorized" && <p className="error">{error}</p>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (token.trim()) signIn(token.trim());
          }}
        >
          <label htmlFor="token">Access token</label>
          <input id="token" className="input mono" type="password" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} />
          <Button type="submit" kind="primary" icon="shield" disabled={!token.trim()}>
            Sign in
          </Button>
        </form>
        <Details summary="Where do I get a token?">
          Run <span className="mono">moat-controller token owner</span> on your controller (or <span className="mono">viewer</span> for read only). The token stays in this browser for this controller. It is not your owner key and can&apos;t allow more on its own.
        </Details>
        <div className="signin-or">or</div>
        <Button kind="secondary" onClick={enterDemo}>
          Explore sample data
        </Button>
        <Fine>Sample data is a fixed example. None of it is about your devices, and its buttons don&apos;t send anything.</Fine>
      </Card>
    </div>
  );
}
