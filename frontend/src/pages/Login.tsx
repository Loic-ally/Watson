import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Hexagon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { postJson } from "@/api";

export default function Login() {
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const navigate = useNavigate();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    const r = await postJson("/api/login", { user, password });
    if (r.ok) navigate("/", { replace: true });
    else setErr("Invalid credentials");
  };

  return (
    <div className="mx-auto mt-[12vh] max-w-sm px-4 text-center">
      <div className="mb-1 flex items-center justify-center gap-2 text-2xl font-extrabold text-primary">
        <Hexagon className="size-6" /> Watson
      </div>
      <p className="mb-6 text-sm text-muted-foreground">Autonomous pentest agent — control panel</p>
      <Card>
        <CardContent className="pt-5">
          <form onSubmit={submit} className="space-y-3 text-left">
            <div>
              <label className="mb-1 block text-sm text-muted-foreground">User</label>
              <Input autoFocus value={user} onChange={(e) => setUser(e.target.value)} />
            </div>
            <div>
              <label className="mb-1 block text-sm text-muted-foreground">Password</label>
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            {err && <div className="text-sm text-destructive">{err}</div>}
            <Button type="submit" className="w-full">Sign in</Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
