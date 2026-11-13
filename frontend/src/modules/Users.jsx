import { useState } from "react";
import { Panel, Grid, StatCard, Badge, Btn, Modal, FormGroup, DataTable, EmptyState } from "../components/UI.jsx";
import { fmtDate, fmtDateTime } from "../utils/dateFormatter.js";

const ROLE_COLORS = {
  admin:    { bg:"#fff1f2", text:"#be123c", border:"#fecdd3" },
  analyst:  { bg:"#f0f5ff", text:"#1340b8", border:"#c1d4ff" },
  operator: { bg:"#f5f3ff", text:"#6d28d9", border:"#ddd6fe" },
  auditor:  { bg:"#fffbeb", text:"#b45309", border:"#fde68a" },
  viewer:   { bg:"#f1f5f9", text:"#475569", border:"#e2e8f0" },
};

function RoleBadge({ role }) {
  const c = ROLE_COLORS[role] || ROLE_COLORS.viewer;
  return (
    <span style={{
      fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700,
      padding:"2px 8px", borderRadius:99,
      background:c.bg, color:c.text, border:`1px solid ${c.border}`,
      textTransform:"uppercase",
    }}>{role}</span>
  );
}

function Avatar({ username, size = 32 }) {
  const initials = username.slice(0,2).toUpperCase();
  const colors = [
    ["#f0f5ff","#2d6bff"], ["#ecfdf5","#059669"], ["#f5f3ff","#7c3aed"],
    ["#fffbeb","#d97706"], ["#fff1f2","#e11d48"],
  ];
  const [bg, text] = colors[username.charCodeAt(0) % colors.length];
  return (
    <div style={{
      width:size, height:size, borderRadius:"50%",
      background:bg, border:`1.5px solid ${text}33`,
      display:"flex", alignItems:"center", justifyContent:"center",
      fontFamily:"var(--font-display)", fontSize:size*0.35, fontWeight:700, color:text,
      flexShrink:0,
    }}>{initials}</div>
  );
}

export default function Users({ appState, onAddUser, onToast }) {
  const { users } = appState;
  const [addModal, setAddModal] = useState(false);
  const [viewUser, setViewUser] = useState(null);
  const [newUser, setNewUser]   = useState({ username:"", email:"", role:"analyst", password:"" });

  const active   = users.filter(u => u.active).length;
  const inactive = users.filter(u => !u.active).length;
  const admins   = users.filter(u => u.role === "admin").length;
  const analysts = users.filter(u => u.role === "analyst").length;

  return (
    <div className="page-enter">
      <Grid cols={4} gap={14} style={{ marginBottom:20 }}>
        <StatCard icon="👤" label="Total Users"     value={users.length} sub="All accounts"      color="#2d6bff" />
        <StatCard icon="✅" label="Active Users"    value={active}       sub="Enabled accounts"  color="#10b981" />
        <StatCard icon="🔐" label="Administrators"  value={admins}       sub="Full access"       color="#e11d48" />
        <StatCard icon="🔍" label="Analysts"        value={analysts}     sub="Security analysts" color="#7c3aed" />
      </Grid>

      {/* Role Distribution */}
      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        <Panel title="Role Distribution" subtitle="Access control overview">
          <div style={{ padding:18 }}>
            {Object.entries(ROLE_COLORS).map(([role, c]) => {
              const count = users.filter(u => u.role === role).length;
              if (count === 0) return null;
              return (
                <div key={role} style={{ display:"flex", alignItems:"center", gap:12,
                  padding:"8px 0", borderBottom:"1px solid #f1f5f9" }}>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:700,
                    padding:"2px 8px", borderRadius:99,
                    background:c.bg, color:c.text, border:`1px solid ${c.border}`,
                    textTransform:"uppercase", minWidth:72, textAlign:"center" }}>{role}</span>
                  <div style={{ flex:1, height:6, background:"#f1f5f9", borderRadius:99, overflow:"hidden" }}>
                    <div style={{ height:"100%", width:`${(count/users.length)*100}%`,
                      background:c.text, borderRadius:99 }} />
                  </div>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:700,
                    color:"var(--color-text-primary)", minWidth:20, textAlign:"right" }}>{count}</span>
                </div>
              );
            })}
          </div>
        </Panel>

        {/* Recent Activity */}
        <Panel title="Recent Activity" subtitle="Login and access events">
          <div>
            {users.slice(0,4).map(u => (
              <div key={u.userId} style={{ display:"flex", alignItems:"center", gap:12,
                padding:"10px 16px", borderBottom:"1px solid #f1f5f9" }}>
                <Avatar username={u.username} size={32} />
                <div style={{ flex:1 }}>
                  <div style={{ fontWeight:600, fontSize:13, color:"var(--color-text-primary)" }}>{u.username}</div>
                  <div style={{ fontSize:11, color:"var(--color-text-tertiary)", marginTop:1 }}>
                    Last login: {u.lastLogin ? fmtDateTime(u.lastLogin) : "Never"}
                  </div>
                </div>
                <RoleBadge role={u.role} />
                <Badge status={u.active ? "active" : "inactive"} size="xs" />
              </div>
            ))}
          </div>
        </Panel>
      </Grid>

      {/* User Table */}
      <Panel title="User Registry" subtitle={`${users.length} accounts · JWT session management`}
        actions={<Btn size="sm" variant="primary" onClick={() => setAddModal(true)}>+ Add User</Btn>}>
        <DataTable
          columns={[
            { label:"User", render:r => (
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <Avatar username={r.username} size={28} />
                <div>
                  <div style={{ fontWeight:600, fontSize:13, color:"var(--color-text-primary)" }}>{r.username}</div>
                  <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--color-text-tertiary)" }}>{r.email}</div>
                </div>
              </div>
            )},
            { label:"Role",       render:r => <RoleBadge role={r.role} /> },
            { label:"Status",     render:r => <Badge status={r.active ? "active" : "inactive"} size="xs" /> },
            { label:"Created",    render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--color-text-tertiary)" }}>
              {fmtDate(r.createdAt)}</span> },
            { label:"Last Login", render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11,
              color:r.lastLogin ? "var(--color-text-secondary)" : "var(--color-text-tertiary)" }}>
              {r.lastLogin ? fmtDateTime(r.lastLogin) : "Never"}</span> },
            { label:"Actions", render:r => (
              <div style={{ display:"flex", gap:6 }}>
                <Btn size="xs" variant="ghost" onClick={() => setViewUser(r)}>View</Btn>
                <Btn size="xs" variant={r.active ? "ghost" : "success"}
                  onClick={() => onToast(`User ${r.username} ${r.active?"disabled":"enabled"}`, r.active?"warning":"success")}
                  style={r.active ? { color:"#e11d48", borderColor:"#fecdd3" } : {}}>
                  {r.active ? "Disable" : "Enable"}
                </Btn>
              </div>
            )},
          ]}
          rows={users}
          emptyText="No users found"
        />
      </Panel>

      {/* View User Modal */}
      <Modal open={!!viewUser} onClose={() => setViewUser(null)} title="User Profile"
        footer={<Btn variant="ghost" onClick={() => setViewUser(null)}>Close</Btn>}>
        {viewUser && (
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:16, marginBottom:20,
              padding:"16px 18px", background:"#f8fafc", borderRadius:"var(--r-lg)", border:"1px solid var(--color-border)" }}>
              <Avatar username={viewUser.username} size={52} />
              <div>
                <div style={{ fontFamily:"var(--font-display)", fontWeight:800, fontSize:18,
                  color:"var(--color-text-primary)", marginBottom:4 }}>{viewUser.username}</div>
                <div style={{ display:"flex", gap:8 }}>
                  <RoleBadge role={viewUser.role} />
                  <Badge status={viewUser.active ? "active" : "inactive"} size="xs" />
                </div>
              </div>
            </div>
            {[
              { label:"Email",         value:viewUser.email,         mono:true  },
              { label:"Role",          value:viewUser.role           },
              { label:"Account Status",value:viewUser.active ? "Active" : "Disabled" },
              { label:"Created",       value:fmtDateTime(viewUser.createdAt), mono:true },
              { label:"Last Login",    value:viewUser.lastLogin ? fmtDateTime(viewUser.lastLogin) : "Never", mono:true },
            ].map(row => (
              <div key={row.label} style={{ display:"flex", justifyContent:"space-between",
                alignItems:"center", padding:"8px 0", borderBottom:"1px solid #f1f5f9" }}>
                <span style={{ fontSize:12, color:"var(--color-text-secondary)", fontWeight:500 }}>{row.label}</span>
                <span style={{ fontSize:12, fontFamily:row.mono?"var(--font-mono)":"var(--font-body)",
                  color:"var(--color-text-primary)", fontWeight:600 }}>{row.value}</span>
              </div>
            ))}
          </div>
        )}
      </Modal>

      {/* Add User Modal */}
      <Modal open={addModal} onClose={() => setAddModal(false)} title="Add New User"
        footer={<>
          <Btn variant="ghost" onClick={() => setAddModal(false)}>Cancel</Btn>
          <Btn variant="primary" onClick={() => {
            if (!newUser.username.trim() || !newUser.email.trim()) { onToast("Username and email required", "warning"); return; }
            if (newUser.password.length < 8) { onToast("Password must be at least 8 characters", "warning"); return; }
            onAddUser({ ...newUser, userId: Date.now(), active:true, createdAt:new Date().toISOString(), lastLogin:null });
            setAddModal(false);
            setNewUser({ username:"", email:"", role:"analyst", password:"" });
            onToast(`User "${newUser.username}" created successfully`, "success");
          }}>Create User</Btn>
        </>}>
        <Grid cols={2} gap={12}>
          <FormGroup label="Username">
            <input value={newUser.username} onChange={e => setNewUser(p=>({...p,username:e.target.value}))} placeholder="analyst3" />
          </FormGroup>
          <FormGroup label="Role">
            <select value={newUser.role} onChange={e => setNewUser(p=>({...p,role:e.target.value}))}>
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
              <option value="operator">Operator</option>
              <option value="auditor">Auditor</option>
              <option value="viewer">Viewer</option>
            </select>
          </FormGroup>
        </Grid>
        <FormGroup label="Email Address">
          <input type="email" value={newUser.email} onChange={e => setNewUser(p=>({...p,email:e.target.value}))} placeholder="user@shieldgod.local" />
        </FormGroup>
        <FormGroup label="Password" hint="Minimum 8 characters. Must include letters and numbers.">
          <input type="password" value={newUser.password} onChange={e => setNewUser(p=>({...p,password:e.target.value}))} placeholder="••••••••••" />
        </FormGroup>
      </Modal>
    </div>
  );
}
