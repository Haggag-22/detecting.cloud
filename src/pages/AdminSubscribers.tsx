import { useState, useEffect } from "react";
import { Layout } from "@/components/Layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Users, Mail, Download, Trash2, Search, Lock } from "lucide-react";
import { toast } from "sonner";

const ADMIN_PIN = "detecting2026";
const STORAGE_KEY = "detecting-cloud-subscribers";

export interface Subscriber {
  email: string;
  subscribedAt: string;
}

export function getSubscribers(): Subscriber[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

export function addSubscriber(email: string): boolean {
  const subs = getSubscribers();
  if (subs.some((s) => s.email === email)) return false;
  subs.push({ email, subscribedAt: new Date().toISOString() });
  localStorage.setItem(STORAGE_KEY, JSON.stringify(subs));
  return true;
}

export default function AdminSubscribers() {
  const [authenticated, setAuthenticated] = useState(false);
  const [pin, setPin] = useState("");
  const [subscribers, setSubscribers] = useState<Subscriber[]>([]);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    if (authenticated) {
      setSubscribers(getSubscribers());
    }
  }, [authenticated]);

  const handleLogin = () => {
    if (pin === ADMIN_PIN) {
      setAuthenticated(true);
      toast.success("Access granted");
    } else {
      toast.error("Incorrect PIN");
    }
  };

  const handleDelete = (email: string) => {
    const updated = subscribers.filter((s) => s.email !== email);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    setSubscribers(updated);
    toast.success("Subscriber removed");
  };

  const handleExport = () => {
    const csv = "Email,Subscribed At\n" + subscribers.map((s) => `${s.email},${s.subscribedAt}`).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "subscribers.csv";
    a.click();
    URL.revokeObjectURL(url);
    toast.success("CSV exported");
  };

  const filtered = subscribers.filter((s) =>
    s.email.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (!authenticated) {
    return (
      <Layout>
        <div className="container py-20 flex items-center justify-center">
          <Card className="w-full max-w-sm">
            <CardHeader className="text-center">
              <Lock className="h-10 w-10 text-primary mx-auto mb-2" />
              <CardTitle>Admin Access</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                type="password"
                placeholder="Enter admin PIN"
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleLogin()}
              />
              <Button onClick={handleLogin} className="w-full">
                Unlock Dashboard
              </Button>
            </CardContent>
          </Card>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="container py-10">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-bold mb-2">Subscriber Dashboard</h1>
            <p className="text-muted-foreground">Manage newsletter subscribers</p>
          </div>
          <Button onClick={handleExport} variant="outline" className="gap-2 shrink-0" disabled={subscribers.length === 0}>
            <Download className="h-4 w-4" /> Export CSV
          </Button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
          <Card>
            <CardContent className="pt-6 text-center">
              <Users className="h-8 w-8 text-primary mx-auto mb-2" />
              <p className="text-3xl font-bold text-foreground">{subscribers.length}</p>
              <p className="text-sm text-muted-foreground">Total Subscribers</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6 text-center">
              <Mail className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
              <p className="text-3xl font-bold text-foreground">
                {subscribers.filter((s) => {
                  const d = new Date(s.subscribedAt);
                  const now = new Date();
                  return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
                }).length}
              </p>
              <p className="text-sm text-muted-foreground">This Month</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6 text-center">
              <Mail className="h-8 w-8 text-orange-400 mx-auto mb-2" />
              <p className="text-3xl font-bold text-foreground">
                {subscribers.filter((s) => {
                  const d = new Date(s.subscribedAt);
                  const now = new Date();
                  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                  return d >= weekAgo;
                }).length}
              </p>
              <p className="text-sm text-muted-foreground">This Week</p>
            </CardContent>
          </Card>
        </div>

        {/* Search */}
        <div className="relative max-w-sm mb-4">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by email..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9"
          />
        </div>

        {/* Table */}
        {subscribers.length === 0 ? (
          <Card>
            <CardContent className="py-16 text-center">
              <Mail className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No subscribers yet. They'll appear here once people subscribe.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="rounded-lg border border-border/50 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/30">
                  <TableHead className="text-foreground">Email</TableHead>
                  <TableHead className="text-foreground">Subscribed</TableHead>
                  <TableHead className="text-foreground w-20">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((sub) => (
                  <TableRow key={sub.email}>
                    <TableCell className="font-medium text-foreground">{sub.email}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(sub.subscribedAt).toLocaleDateString("en-US", {
                        year: "numeric", month: "short", day: "numeric",
                      })}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDelete(sub.email)}
                        className="text-destructive hover:text-destructive"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </Layout>
  );
}
