import React from "react";

type Props = { children: React.ReactNode };
type State = { error: Error | null };

/**
 * Shows what broke instead of a blank page.
 *
 * React unmounts the whole tree when a component throws during render, so in a
 * review harness one unhandled fixture turns the entire screen black and says
 * nothing about why. This prints the error where the UI would have been.
 *
 * Preview only. The shipped app has no such catch-all, deliberately: a wallet
 * that half-renders after an error is worse than one that refuses to.
 */
export class PreviewErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div
        style={{
          padding: "32px",
          margin: "24px",
          border: "1px solid #b4483c",
          borderRadius: "12px",
          background: "#150a09",
          color: "#f0d6d3",
          font: "13px/1.6 ui-monospace, Consolas, monospace",
        }}
      >
        <strong style={{ display: "block", marginBottom: "12px", fontSize: "15px" }}>
          The preview tree threw during render
        </strong>
        <div style={{ marginBottom: "12px" }}>{error.message}</div>
        <pre style={{ margin: 0, overflow: "auto", opacity: 0.75, whiteSpace: "pre-wrap" }}>
          {error.stack}
        </pre>
        <p style={{ marginTop: "16px", opacity: 0.7 }}>
          Usually a missing or wrongly shaped fixture in preview/ipcMock.ts. The console lists
          every command that answered with no fixture.
        </p>
      </div>
    );
  }
}
