import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "./components/Layout";
import { checkAuth } from "./api";
import Login from "./pages/Login";
import Chat from "./pages/Chat";
import Dashboard from "./pages/Dashboard";
import Reports from "./pages/Reports";
import Report from "./pages/Report";
import Knowledge from "./pages/Knowledge";

function RequireAuth({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<"checking" | "yes" | "no">("checking");
  const loc = useLocation();
  useEffect(() => {
    checkAuth().then((ok) => setState(ok ? "yes" : "no"));
  }, [loc.pathname]);
  if (state === "checking")
    return <div className="p-10 text-muted-foreground">Loading…</div>;
  if (state === "no") return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<RequireAuth><Chat /></RequireAuth>} />
      <Route path="/dashboard" element={<RequireAuth><Dashboard /></RequireAuth>} />
      <Route path="/reports" element={<RequireAuth><Reports /></RequireAuth>} />
      <Route path="/report/:name" element={<RequireAuth><Report /></RequireAuth>} />
      <Route path="/knowledge" element={<RequireAuth><Knowledge /></RequireAuth>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
