/** Layered visionOS-style canvas: drifting light orbs, a dot grid and film grain. Purely decorative. */
export function Ambient() {
  return (
    <div className="ambient" aria-hidden>
      <div className="orb orb-indigo" />
      <div className="orb orb-cyan" />
      <div className="orb orb-emerald" />
      <div className="orb orb-crimson-left" />
      <div className="orb orb-crimson-right" />
      <div className="dot-grid" />
      <div className="grain" />
    </div>
  );
}
