/**
 * One colour per agent, held for the whole page.
 *
 * Every dot, chip and trace row is coloured by agent, so a glance at a
 * thread's pulse line says who was talking without reading a
 * name. The palette is twelve inks that stay apart on the paper background;
 * an agent's colour is its seat in team.json, so it never changes between
 * panels or reloads. Ids outside the team (the harness, a probe) hash in.
 */
import { useMemo } from "react";

export const AGENT_INKS = [
  "#1f6f5f", // kelp
  "#b5542b", // clay
  "#2c4660", // slate
  "#7a5c1e", // ochre
  "#6b3d7a", // plum
  "#2f5a1c", // moss
  "#1f5f8a", // lake
  "#a8322f", // brick
  "#4b4b8f", // indigo
  "#8a5a00", // saffron
  "#5c6b1f", // olive
  "#8f3f5f", // wine
];

export const SYSTEM_INK = "#8b2e2b";

function hashOf(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return h;
}

export function agentColour(id: string, seats: string[]): string {
  if (id === "system" || id === "harness") return SYSTEM_INK;
  const seat = seats.indexOf(id);
  return AGENT_INKS[(seat >= 0 ? seat : hashOf(id)) % AGENT_INKS.length];
}

export function useAgentColours(agents: Array<{ id: string }> | undefined): (id: string) => string {
  return useMemo(() => {
    const seats = (agents ?? []).map((a) => a.id);
    return (id: string) => agentColour(id, seats);
  }, [agents]);
}
