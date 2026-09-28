import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/app-shell";
import { OverviewScreen } from "@/screens/overview";
import { KickoffScreen } from "@/screens/kickoff";
import { SwarmDetailScreen } from "@/screens/swarm-detail";
import { ExaminersScreen } from "@/screens/examiners";
import { EmptyState } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

export function App() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<OverviewScreen />} />
        <Route path="/new" element={<KickoffScreen />} />
        <Route path="/examiners" element={<ExaminersScreen />} />
        <Route path="/swarms/:id" element={<SwarmDetailScreen />} />
        <Route path="/swarms/:id/:tab" element={<SwarmDetailScreen />} />
        <Route path="/swarms/:id/:tab/:sub" element={<SwarmDetailScreen />} />
        <Route path="/swarms" element={<Navigate to="/" replace />} />
        <Route
          path="*"
          element={
            <EmptyState
              title="No such page"
              hint="The web app has four places: the swarm overview, the kickoff form, one page per swarm, and the examiners enrolled on this install."
              action={
                <Button asChild variant="secondary">
                  <Link to="/">Back to swarms</Link>
                </Button>
              }
            />
          }
        />
      </Routes>
    </AppShell>
  );
}
