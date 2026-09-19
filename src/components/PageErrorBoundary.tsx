import { Component, type ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { Layout } from "@/components/Layout";

type InnerProps = {
  children: ReactNode;
  resetKey: string;
};

type InnerState = {
  error: Error | null;
};

class PageErrorBoundaryInner extends Component<InnerProps, InnerState> {
  state: InnerState = { error: null };

  static getDerivedStateFromError(error: Error): InnerState {
    return { error };
  }

  componentDidUpdate(prevProps: InnerProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return (
        <Layout>
          <div className="container max-w-2xl">
            <h1 className="font-display text-2xl font-bold mb-3">This page could not be displayed</h1>
            <p className="text-muted-foreground mb-6">
              Something went wrong while loading this page. The rest of the site is still available.
            </p>
            <div className="flex flex-wrap gap-3">
              <Link
                to="/techniques"
                className="inline-flex items-center rounded-lg border border-border/50 bg-card px-4 py-2 text-sm font-medium hover:border-primary/30 transition-colors"
              >
                Attack Techniques
              </Link>
              <Link
                to="/attack-graph"
                className="inline-flex items-center rounded-lg border border-border/50 bg-card px-4 py-2 text-sm font-medium hover:border-primary/30 transition-colors"
              >
                Attack Graph
              </Link>
              <Link to="/" className="inline-flex items-center text-sm text-primary hover:underline">
                Back to Home
              </Link>
            </div>
          </div>
        </Layout>
      );
    }

    return this.props.children;
  }
}

export function PageErrorBoundary({ children }: { children: ReactNode }) {
  const location = useLocation();
  return (
    <PageErrorBoundaryInner resetKey={`${location.pathname}${location.search}`}>
      {children}
    </PageErrorBoundaryInner>
  );
}
