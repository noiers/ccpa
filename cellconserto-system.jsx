import { useState, useEffect, useCallback, useRef } from "react";

// ============================================================
// SECURITY & CRYPTO UTILITIES
// ============================================================
const Security = {
  hashPassword: async (password) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + "cellconserto_salt_2024");
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  },
  generateToken: () => {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
  },
  generateId: () => {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  },
  getClientIP: () => {
    // Simulate IP for demo
    return "192.168." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255);
  },
  validatePhone: (phone) => {
    const cleaned = phone.replace(/\D/g, "");
    return cleaned.length >= 10 && cleaned.length <= 11;
  },
  validateEmail: (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
  sanitize: (str) => str.replace(/[<>"'&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;", "&": "&amp;" }[c])),
  escapeSQL: (str) => str.replace(/'/g, "''").replace(/;/g, ""),
};

// ============================================================
// DATABASE (localStorage)
// ============================================================
const DB = {
  get: (key) => {
    try { return JSON.parse(localStorage.getItem("cellconserto_" + key) || "null"); }
    catch { return null; }
  },
  set: (key, value) => {
    try { localStorage.setItem("cellconserto_" + key, JSON.stringify(value)); return true; }
    catch { return false; }
  },
  init: () => {
    if (!DB.get("initialized")) {
      DB.set("users", []);
      DB.set("requests", []);
      DB.set("access_logs", []);
      DB.set("blocked_ips", []);
      DB.set("rate_limits", {});
      DB.set("site_config", {
        banner: "",
        bannerActive: false,
        heroTitle: "CellConserto.PA",
        heroSubtitle: "Conserto de Celulares Android — Rápido, Confiável e Seguro",
        aboutText: "Especialistas em conserto de celulares Android com peças originais e garantia.",
        whatsapp: "+55 42 9153-3877",
      });
      DB.set("admin_session", null);
      DB.set("initialized", true);
      // Seed admin
      Security.hashPassword("Admin@CellPA2024!").then(hash => {
        DB.set("admin_hash", hash);
        DB.set("admin_ip_whitelist", []);
      });
    }
  },
  log: (action, ip, details = {}) => {
    const logs = DB.get("access_logs") || [];
    logs.unshift({ id: Security.generateId(), action, ip, details, timestamp: new Date().toISOString() });
    DB.set("access_logs", logs.slice(0, 500));
  },
  checkRateLimit: (ip, action, maxAttempts = 5, windowMs = 300000) => {
    const limits = DB.get("rate_limits") || {};
    const key = `${ip}_${action}`;
    const now = Date.now();
    if (!limits[key]) limits[key] = { attempts: 0, firstAttempt: now };
    if (now - limits[key].firstAttempt > windowMs) {
      limits[key] = { attempts: 0, firstAttempt: now };
    }
    limits[key].attempts++;
    DB.set("rate_limits", limits);
    return limits[key].attempts <= maxAttempts;
  },
};

// ============================================================
// AUTH
// ============================================================
const Auth = {
  login: async (email, password, ip) => {
    if (!DB.checkRateLimit(ip, "login")) {
      DB.log("RATE_LIMIT_LOGIN", ip, { email });
      throw new Error("Muitas tentativas. Aguarde 5 minutos.");
    }
    const users = DB.get("users") || [];
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      DB.log("LOGIN_FAILED_USER", ip, { email });
      throw new Error("Credenciais inválidas.");
    }
    if (user.blocked) {
      DB.log("LOGIN_BLOCKED_USER", ip, { email });
      throw new Error("Sua conta foi bloqueada. Entre em contato.");
    }
    const hash = await Security.hashPassword(password);
    if (hash !== user.passwordHash) {
      DB.log("LOGIN_FAILED_PASS", ip, { email });
      throw new Error("Credenciais inválidas.");
    }
    const token = Security.generateToken();
    const session = { userId: user.id, token, ip, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 8 * 3600000).toISOString() };
    DB.set("user_session", session);
    DB.log("LOGIN_SUCCESS", ip, { email, userId: user.id });
    return { user: { ...user, passwordHash: undefined }, token };
  },
  adminLogin: async (password, ip) => {
    if (!DB.checkRateLimit(ip, "admin_login", 3, 600000)) {
      DB.log("ADMIN_RATE_LIMIT", ip);
      throw new Error("Muitas tentativas. Aguarde 10 minutos.");
    }
    const hash = await Security.hashPassword(password);
    const adminHash = DB.get("admin_hash");
    if (hash !== adminHash) {
      DB.log("ADMIN_LOGIN_FAILED", ip);
      throw new Error("Senha administrativa incorreta.");
    }
    const token = Security.generateToken();
    const knownIPs = DB.get("admin_ip_whitelist") || [];
    const isNewIP = !knownIPs.includes(ip);
    if (isNewIP) {
      DB.log("ADMIN_NEW_IP", ip, { alert: "NOVO IP NO SISTEMA ADMIN!" });
      const updated = [...knownIPs, ip].slice(-10);
      DB.set("admin_ip_whitelist", updated);
    }
    const session = { token, ip, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 4 * 3600000).toISOString(), isNewIP };
    DB.set("admin_session", session);
    DB.log("ADMIN_LOGIN_SUCCESS", ip, { isNewIP });
    return { token, isNewIP };
  },
  logout: () => { DB.set("user_session", null); },
  adminLogout: () => { DB.set("admin_session", null); },
  getCurrentUser: () => {
    const session = DB.get("user_session");
    if (!session) return null;
    if (new Date(session.expiresAt) < new Date()) { DB.set("user_session", null); return null; }
    const users = DB.get("users") || [];
    return users.find(u => u.id === session.userId) || null;
  },
  isAdminValid: () => {
    const session = DB.get("admin_session");
    if (!session) return false;
    if (new Date(session.expiresAt) < new Date()) { DB.set("admin_session", null); return false; }
    return true;
  },
  register: async (data, ip) => {
    if (!DB.checkRateLimit(ip, "register", 3, 3600000)) throw new Error("Muitos cadastros do mesmo IP.");
    const users = DB.get("users") || [];
    if (users.find(u => u.email.toLowerCase() === data.email.toLowerCase())) throw new Error("Email já cadastrado.");
    if (!Security.validateEmail(data.email)) throw new Error("Email inválido.");
    if (!Security.validatePhone(data.phone)) throw new Error("Telefone inválido.");
    if (data.password.length < 8) throw new Error("Senha mínima de 8 caracteres.");
    if (!/[A-Z]/.test(data.password)) throw new Error("Senha deve ter ao menos uma maiúscula.");
    if (!/[0-9]/.test(data.password)) throw new Error("Senha deve ter ao menos um número.");
    const passwordHash = await Security.hashPassword(data.password);
    const user = { id: Security.generateId(), name: Security.sanitize(data.name), email: data.email.toLowerCase(), phone: data.phone, passwordHash, blocked: false, rating: null, createdAt: new Date().toISOString(), registrationIP: ip };
    users.push(user);
    DB.set("users", users);
    DB.log("REGISTER", ip, { email: data.email });
    return { user: { ...user, passwordHash: undefined } };
  },
};

// ============================================================
// REQUESTS SERVICE
// ============================================================
const RequestService = {
  create: (data, userId, ip) => {
    const reqs = DB.get("requests") || [];
    const blocked = DB.get("blocked_ips") || [];
    if (blocked.includes(ip)) throw new Error("Acesso bloqueado.");
    const req = {
      id: Security.generateId(),
      userId,
      ip,
      name: Security.sanitize(data.name),
      phone: data.phone,
      brand: Security.sanitize(data.brand),
      model: Security.sanitize(data.model),
      description: Security.sanitize(data.description),
      serviceType: data.serviceType,
      status: "Pendente",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      adminNotes: "",
      rating: null,
    };
    reqs.unshift(req);
    DB.set("requests", reqs);
    DB.log("REQUEST_CREATED", ip, { requestId: req.id, userId });
    return req;
  },
  getAll: () => DB.get("requests") || [],
  getByUser: (userId) => (DB.get("requests") || []).filter(r => r.userId === userId),
  updateStatus: (id, status, adminNotes = "") => {
    const reqs = DB.get("requests") || [];
    const idx = reqs.findIndex(r => r.id === id);
    if (idx === -1) throw new Error("Pedido não encontrado.");
    reqs[idx].status = status;
    reqs[idx].adminNotes = Security.sanitize(adminNotes);
    reqs[idx].updatedAt = new Date().toISOString();
    DB.set("requests", reqs);
    return reqs[idx];
  },
  rate: (id, rating, userId) => {
    const reqs = DB.get("requests") || [];
    const idx = reqs.findIndex(r => r.id === id && r.userId === userId);
    if (idx === -1) throw new Error("Pedido não encontrado.");
    reqs[idx].rating = rating;
    DB.set("requests", reqs);
    return reqs[idx];
  },
  blockUser: (userId, ip) => {
    const users = DB.get("users") || [];
    const idx = users.findIndex(u => u.id === userId);
    if (idx !== -1) { users[idx].blocked = true; DB.set("users", users); }
    const blocked = DB.get("blocked_ips") || [];
    if (ip && !blocked.includes(ip)) { blocked.push(ip); DB.set("blocked_ips", blocked); }
    DB.log("USER_BLOCKED", ip, { userId });
  },
};

// ============================================================
// COMPONENTS
// ============================================================

// Toast Notifications
function Toast({ toasts, remove }) {
  return (
    <div style={{ position: "fixed", bottom: 24, right: 24, zIndex: 9999, display: "flex", flexDirection: "column", gap: 10 }}>
      {toasts.map(t => (
        <div key={t.id} onClick={() => remove(t.id)} style={{
          background: t.type === "error" ? "#ff4444" : t.type === "warning" ? "#ffaa00" : "#00d68f",
          color: "#fff", padding: "12px 20px", borderRadius: 10, cursor: "pointer",
          fontFamily: "'Syne', sans-serif", fontSize: 14, fontWeight: 600,
          boxShadow: "0 8px 32px rgba(0,0,0,0.4)", maxWidth: 320,
          animation: "slideIn 0.3s ease", display: "flex", alignItems: "center", gap: 10,
        }}>
          <span>{t.type === "error" ? "⚠" : t.type === "warning" ? "🔔" : "✓"}</span>
          {t.message}
        </div>
      ))}
    </div>
  );
}

function useToast() {
  const [toasts, setToasts] = useState([]);
  const add = useCallback((message, type = "success") => {
    const id = Security.generateId();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  }, []);
  const remove = useCallback((id) => setToasts(prev => prev.filter(t => t.id !== id)), []);
  return { toasts, add, remove };
}

// Input Field
function Field({ label, type = "text", value, onChange, placeholder, required, error, icon, mask }) {
  const handleChange = (e) => {
    let val = e.target.value;
    if (mask === "phone") val = val.replace(/\D/g, "").replace(/(\d{2})(\d{5})(\d{4})/, "($1) $2-$3");
    onChange(val);
  };
  return (
    <div style={{ marginBottom: 20 }}>
      <label style={{ display: "block", color: "#8892a4", fontSize: 12, fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 8, fontFamily: "'Syne', sans-serif" }}>{label}{required && " *"}</label>
      <div style={{ position: "relative" }}>
        {icon && <span style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)", fontSize: 16, pointerEvents: "none" }}>{icon}</span>}
        {type === "textarea" ? (
          <textarea value={value} onChange={handleChange} placeholder={placeholder} rows={4}
            style={{ width: "100%", background: "#0d1117", border: `1px solid ${error ? "#ff4444" : "#1e2a3a"}`, borderRadius: 10, padding: "12px 14px", color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 14, resize: "vertical", outline: "none", boxSizing: "border-box", transition: "border-color 0.2s" }} />
        ) : (
          <input type={type} value={value} onChange={handleChange} placeholder={placeholder}
            style={{ width: "100%", background: "#0d1117", border: `1px solid ${error ? "#ff4444" : "#1e2a3a"}`, borderRadius: 10, padding: `12px ${icon ? "14px 12px 40px" : "14px"}`, color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 14, outline: "none", boxSizing: "border-box", transition: "border-color 0.2s" }} />
        )}
      </div>
      {error && <p style={{ color: "#ff4444", fontSize: 12, marginTop: 4, fontFamily: "'Syne', sans-serif" }}>{error}</p>}
    </div>
  );
}

// Button
function Btn({ children, onClick, variant = "primary", size = "md", fullWidth, disabled, loading }) {
  const styles = {
    primary: { background: "linear-gradient(135deg, #00d68f, #00b4d8)", color: "#000", border: "none" },
    danger: { background: "linear-gradient(135deg, #ff4444, #cc0000)", color: "#fff", border: "none" },
    warning: { background: "linear-gradient(135deg, #ffaa00, #ff7700)", color: "#000", border: "none" },
    ghost: { background: "transparent", color: "#8892a4", border: "1px solid #1e2a3a" },
    outline: { background: "transparent", color: "#00d68f", border: "1px solid #00d68f" },
  };
  const sizes = { sm: { padding: "6px 14px", fontSize: 12 }, md: { padding: "12px 24px", fontSize: 14 }, lg: { padding: "16px 32px", fontSize: 16 } };
  return (
    <button onClick={disabled || loading ? undefined : onClick} style={{
      ...styles[variant], ...sizes[size],
      width: fullWidth ? "100%" : "auto",
      borderRadius: 10, fontFamily: "'Syne', sans-serif", fontWeight: 700,
      cursor: disabled || loading ? "not-allowed" : "pointer",
      opacity: disabled || loading ? 0.6 : 1,
      transition: "all 0.2s", letterSpacing: "0.05em",
      display: "inline-flex", alignItems: "center", gap: 8,
    }}>
      {loading ? "⟳" : children}
    </button>
  );
}

// Status Badge
function StatusBadge({ status }) {
  const map = {
    "Pendente": { bg: "#ffaa0022", color: "#ffaa00", icon: "⏳" },
    "Aceito": { bg: "#00d68f22", color: "#00d68f", icon: "✓" },
    "Recusado": { bg: "#ff444422", color: "#ff4444", icon: "✗" },
    "Em andamento": { bg: "#00b4d822", color: "#00b4d8", icon: "🔧" },
    "Finalizado": { bg: "#8b5cf622", color: "#8b5cf6", icon: "✅" },
  };
  const s = map[status] || map["Pendente"];
  return (
    <span style={{ background: s.bg, color: s.color, padding: "4px 12px", borderRadius: 20, fontSize: 12, fontWeight: 700, fontFamily: "'Syne', sans-serif", display: "inline-flex", alignItems: "center", gap: 4 }}>
      {s.icon} {status}
    </span>
  );
}

// Card
function Card({ children, style = {} }) {
  return (
    <div style={{ background: "#0d1117", border: "1px solid #1e2a3a", borderRadius: 16, padding: 24, ...style }}>
      {children}
    </div>
  );
}

// Modal
function Modal({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }} onClick={onClose}>
      <div style={{ background: "#0d1117", border: "1px solid #1e2a3a", borderRadius: 20, padding: 32, maxWidth: 560, width: "100%", maxHeight: "90vh", overflowY: "auto" }} onClick={e => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
          <h2 style={{ margin: 0, color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 20 }}>{title}</h2>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#8892a4", cursor: "pointer", fontSize: 20 }}>✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

// Star Rating
function StarRating({ value, onChange, readOnly }) {
  return (
    <div style={{ display: "flex", gap: 4 }}>
      {[1,2,3,4,5].map(s => (
        <span key={s} onClick={() => !readOnly && onChange && onChange(s)} style={{ fontSize: 24, cursor: readOnly ? "default" : "pointer", color: s <= (value || 0) ? "#ffaa00" : "#1e2a3a" }}>★</span>
      ))}
    </div>
  );
}

// ============================================================
// PAGES
// ============================================================

// Landing Page
function LandingPage({ onNavigate, currentUser, config }) {
  const whatsappUrl = `https://wa.me/${(config?.whatsapp || "+55 42 9153-3877").replace(/\D/g, "")}`;
  return (
    <div>
      {/* Hero */}
      <section style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center", padding: "40px 20px", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", inset: 0, background: "radial-gradient(ellipse at 50% 0%, #00d68f15 0%, transparent 70%)", pointerEvents: "none" }} />
        <div style={{ maxWidth: 800, position: "relative", zIndex: 1 }}>
          <div style={{ display: "inline-block", background: "#00d68f15", border: "1px solid #00d68f44", borderRadius: 40, padding: "6px 20px", marginBottom: 24 }}>
            <span style={{ color: "#00d68f", fontFamily: "'Syne', sans-serif", fontSize: 13, fontWeight: 700, letterSpacing: "0.15em" }}>🔧 ESPECIALISTAS EM ANDROID</span>
          </div>
          <h1 style={{ fontFamily: "'Syne', sans-serif", fontSize: "clamp(40px, 8vw, 80px)", fontWeight: 900, color: "#e6edf3", margin: "0 0 16px", lineHeight: 1.1 }}>
            {config?.heroTitle || "CellConserto.PA"}
          </h1>
          <p style={{ color: "#8892a4", fontSize: 18, maxWidth: 560, margin: "0 auto 40px", fontFamily: "'Syne', sans-serif", lineHeight: 1.7 }}>
            {config?.heroSubtitle || "Conserto de Celulares Android — Rápido, Confiável e Seguro"}
          </p>
          <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
            <Btn onClick={() => onNavigate("request")} size="lg">📋 Solicitar Serviço</Btn>
            <Btn onClick={() => window.open(whatsappUrl, "_blank")} variant="outline" size="lg">💬 WhatsApp</Btn>
          </div>
        </div>
      </section>

      {/* Services */}
      <section style={{ padding: "80px 20px", maxWidth: 1100, margin: "0 auto" }}>
        <h2 style={{ textAlign: "center", fontFamily: "'Syne', sans-serif", fontSize: 36, fontWeight: 900, color: "#e6edf3", marginBottom: 48 }}>Nossos Serviços</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 24 }}>
          {[
            { icon: "📱", title: "Troca de Tela", desc: "Display original do aparelho com garantia. Qualidade assegurada." },
            { icon: "🔋", title: "Troca de Bateria", desc: "Bateria original para máxima duração e performance do seu dispositivo." },
            { icon: "🧹", title: "Limpeza Interna", desc: "Limpeza completa interna e externa, devolvendo vida ao seu aparelho." },
          ].map((s, i) => (
            <Card key={i} style={{ textAlign: "center" }}>
              <div style={{ fontSize: 48, marginBottom: 16 }}>{s.icon}</div>
              <h3 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 20, fontWeight: 700, marginBottom: 8 }}>{s.title}</h3>
              <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", lineHeight: 1.7, margin: 0 }}>{s.desc}</p>
            </Card>
          ))}
        </div>
      </section>

      {/* Warning */}
      <section style={{ padding: "0 20px 80px", maxWidth: 800, margin: "0 auto" }}>
        <Card style={{ borderColor: "#ffaa0044", background: "#ffaa0008", textAlign: "center" }}>
          <span style={{ fontSize: 32 }}>⚠️</span>
          <h3 style={{ color: "#ffaa00", fontFamily: "'Syne', sans-serif", fontWeight: 700, margin: "12px 0 8px" }}>AVISO IMPORTANTE</h3>
          <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", lineHeight: 1.7, margin: 0 }}>
            Prazo de <strong style={{ color: "#ffaa00" }}>45 dias</strong> para retirar seu celular. Após esse prazo, o aparelho será considerado abandonado e poderá ser vendido.
          </p>
        </Card>
      </section>

      {/* Contact */}
      <section style={{ padding: "0 20px 80px", maxWidth: 700, margin: "0 auto", textAlign: "center" }}>
        <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: 36, fontWeight: 900, color: "#e6edf3", marginBottom: 32 }}>Contato</h2>
        <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
          {[
            { icon: "📞", text: "+55 42 9153-3877" },
            { icon: "📧", text: "cell.consertos.pa@gmail.com" },
            { icon: "📷", text: "@cell.conserto.pa" },
          ].map((c, i) => (
            <Card key={i} style={{ display: "inline-flex", alignItems: "center", gap: 10, padding: "14px 20px" }}>
              <span style={{ fontSize: 20 }}>{c.icon}</span>
              <span style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 14 }}>{c.text}</span>
            </Card>
          ))}
        </div>
      </section>
    </div>
  );
}

// Auth Page
function AuthPage({ onSuccess, toast }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ name: "", email: "", phone: "", password: "", confirm: "" });
  const [loading, setLoading] = useState(false);
  const ip = Security.getClientIP();

  const f = (field) => (val) => setForm(p => ({ ...p, [field]: val }));

  const handleLogin = async () => {
    setLoading(true);
    try {
      const { user } = await Auth.login(form.email, form.password, ip);
      toast("Bem-vindo de volta! 👋", "success");
      onSuccess(user);
    } catch (e) { toast(e.message, "error"); }
    setLoading(false);
  };

  const handleRegister = async () => {
    if (form.password !== form.confirm) { toast("Senhas não coincidem.", "error"); return; }
    setLoading(true);
    try {
      const { user } = await Auth.register(form, ip);
      // Auto-login
      const { user: logged } = await Auth.login(form.email, form.password, ip);
      toast("Conta criada com sucesso! 🎉", "success");
      onSuccess(logged);
    } catch (e) { toast(e.message, "error"); }
    setLoading(false);
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <Card style={{ maxWidth: 440, width: "100%" }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 48, marginBottom: 12 }}>🔧</div>
          <h2 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 24, fontWeight: 900, margin: 0 }}>
            {mode === "login" ? "Entrar" : "Criar Conta"}
          </h2>
        </div>

        {mode === "register" && <Field label="Nome Completo" value={form.name} onChange={f("name")} placeholder="Seu nome" required icon="👤" />}
        <Field label="Email" type="email" value={form.email} onChange={f("email")} placeholder="seu@email.com" required icon="📧" />
        {mode === "register" && <Field label="Telefone" value={form.phone} onChange={f("phone")} placeholder="(42) 99999-9999" required icon="📞" mask="phone" />}
        <Field label="Senha" type="password" value={form.password} onChange={f("password")} placeholder="••••••••" required icon="🔒" />
        {mode === "register" && <Field label="Confirmar Senha" type="password" value={form.confirm} onChange={f("confirm")} placeholder="••••••••" required icon="🔒" />}

        {mode === "register" && (
          <div style={{ background: "#0d1117", border: "1px solid #1e2a3a", borderRadius: 10, padding: 12, marginBottom: 20 }}>
            <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 12, margin: 0, lineHeight: 1.8 }}>
              ✓ Mín. 8 caracteres &nbsp;|&nbsp; ✓ Uma letra maiúscula &nbsp;|&nbsp; ✓ Um número
            </p>
          </div>
        )}

        <Btn onClick={mode === "login" ? handleLogin : handleRegister} fullWidth loading={loading} size="lg">
          {mode === "login" ? "Entrar" : "Criar Conta"}
        </Btn>

        <p style={{ textAlign: "center", marginTop: 20, color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 14 }}>
          {mode === "login" ? "Não tem conta?" : "Já tem conta?"}{" "}
          <span onClick={() => setMode(mode === "login" ? "register" : "login")} style={{ color: "#00d68f", cursor: "pointer", fontWeight: 700 }}>
            {mode === "login" ? "Criar agora" : "Entrar"}
          </span>
        </p>
      </Card>
    </div>
  );
}

// Request Form
function RequestPage({ currentUser, toast, onNavigate }) {
  const [form, setForm] = useState({
    name: currentUser?.name || "",
    phone: currentUser?.phone || "",
    brand: "",
    model: "",
    description: "",
    serviceType: "Conserto",
  });
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const ip = Security.getClientIP();

  const f = (field) => (val) => setForm(p => ({ ...p, [field]: val }));

  const handleSubmit = () => {
    if (!form.name || !form.phone || !form.brand || !form.model || !form.description) {
      toast("Preencha todos os campos obrigatórios.", "error"); return;
    }
    if (!Security.validatePhone(form.phone)) { toast("Telefone inválido.", "error"); return; }
    setLoading(true);
    try {
      RequestService.create(form, currentUser?.id || "guest", ip);
      setSubmitted(true);
      toast("Solicitação enviada com sucesso! ✓", "success");
    } catch (e) { toast(e.message, "error"); }
    setLoading(false);
  };

  if (submitted) return (
    <div style={{ minHeight: "80vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <Card style={{ maxWidth: 480, width: "100%", textAlign: "center" }}>
        <div style={{ fontSize: 64, marginBottom: 16 }}>✅</div>
        <h2 style={{ color: "#00d68f", fontFamily: "'Syne', sans-serif", fontSize: 28, fontWeight: 900, marginBottom: 12 }}>Solicitação Enviada!</h2>
        <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", lineHeight: 1.7, marginBottom: 32 }}>
          Recebemos seu pedido. Em breve entraremos em contato para confirmar o atendimento.
        </p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <Btn onClick={() => setSubmitted(false)} variant="ghost">Nova Solicitação</Btn>
          {currentUser && <Btn onClick={() => onNavigate("dashboard")}>Meus Pedidos</Btn>}
          <Btn onClick={() => onNavigate("home")} variant="outline">Início</Btn>
        </div>
      </Card>
    </div>
  );

  return (
    <div style={{ padding: "60px 20px", maxWidth: 640, margin: "0 auto" }}>
      <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: 32, fontWeight: 900, color: "#e6edf3", marginBottom: 8 }}>Solicitar Serviço</h2>
      <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", marginBottom: 40 }}>Preencha as informações abaixo para iniciar seu atendimento.</p>

      <Card>
        <Field label="Nome Completo" value={form.name} onChange={f("name")} placeholder="Seu nome completo" required icon="👤" />
        <Field label="Telefone" value={form.phone} onChange={f("phone")} placeholder="(42) 99999-9999" required icon="📞" mask="phone" />
        
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <Field label="Marca do Celular" value={form.brand} onChange={f("brand")} placeholder="Samsung, Motorola..." required icon="📱" />
          <Field label="Modelo" value={form.model} onChange={f("model")} placeholder="Galaxy A54, Moto G..." required icon="📋" />
        </div>

        <div style={{ marginBottom: 20 }}>
          <label style={{ display: "block", color: "#8892a4", fontSize: 12, fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 8, fontFamily: "'Syne', sans-serif" }}>Tipo de Serviço *</label>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {["Conserto", "Limpeza", "Troca de Tela", "Troca de Bateria", "Outro"].map(s => (
              <button key={s} onClick={() => f("serviceType")(s)} style={{
                padding: "8px 16px", borderRadius: 8, border: `1px solid ${form.serviceType === s ? "#00d68f" : "#1e2a3a"}`,
                background: form.serviceType === s ? "#00d68f15" : "transparent",
                color: form.serviceType === s ? "#00d68f" : "#8892a4",
                fontFamily: "'Syne', sans-serif", fontSize: 13, fontWeight: 600, cursor: "pointer",
              }}>{s}</button>
            ))}
          </div>
        </div>

        <Field label="Descrição do Problema" type="textarea" value={form.description} onChange={f("description")} placeholder="Descreva detalhadamente o problema do seu aparelho..." required />

        <Btn onClick={handleSubmit} fullWidth loading={loading} size="lg">📨 Enviar Solicitação</Btn>
      </Card>
    </div>
  );
}

// Client Dashboard
function DashboardPage({ currentUser, toast }) {
  const [requests, setRequests] = useState([]);
  const [ratingModal, setRatingModal] = useState(null);
  const [rating, setRating] = useState(0);

  useEffect(() => {
    if (currentUser) setRequests(RequestService.getByUser(currentUser.id));
  }, [currentUser]);

  const handleRate = () => {
    try {
      RequestService.rate(ratingModal.id, rating, currentUser.id);
      setRequests(RequestService.getByUser(currentUser.id));
      setRatingModal(null);
      toast("Avaliação enviada! Obrigado 🌟", "success");
    } catch (e) { toast(e.message, "error"); }
  };

  if (!currentUser) return (
    <div style={{ padding: "80px 20px", textAlign: "center" }}>
      <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif" }}>Faça login para ver seus pedidos.</p>
    </div>
  );

  return (
    <div style={{ padding: "60px 20px", maxWidth: 900, margin: "0 auto" }}>
      <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: 32, fontWeight: 900, color: "#e6edf3", marginBottom: 8 }}>Meus Pedidos</h2>
      <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", marginBottom: 40 }}>Acompanhe o status dos seus serviços.</p>

      {requests.length === 0 ? (
        <Card style={{ textAlign: "center" }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>📭</div>
          <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif" }}>Nenhuma solicitação encontrada.</p>
        </Card>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {requests.map(r => (
            <Card key={r.id}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12, marginBottom: 16 }}>
                <div>
                  <h3 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 18, fontWeight: 700, margin: "0 0 4px" }}>{r.brand} {r.model}</h3>
                  <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 13, margin: 0 }}>
                    {r.serviceType} • {new Date(r.createdAt).toLocaleDateString("pt-BR")}
                  </p>
                </div>
                <StatusBadge status={r.status} />
              </div>
              <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 14, margin: "0 0 12px", lineHeight: 1.6 }}>{r.description}</p>
              {r.adminNotes && (
                <div style={{ background: "#00d68f08", border: "1px solid #00d68f22", borderRadius: 8, padding: "10px 14px", marginBottom: 12 }}>
                  <p style={{ color: "#00d68f", fontFamily: "'Syne', sans-serif", fontSize: 13, margin: 0 }}>💬 <strong>Nota do técnico:</strong> {r.adminNotes}</p>
                </div>
              )}
              {r.status === "Finalizado" && !r.rating && (
                <Btn onClick={() => { setRatingModal(r); setRating(0); }} variant="outline" size="sm">⭐ Avaliar Serviço</Btn>
              )}
              {r.rating && <StarRating value={r.rating} readOnly />}
            </Card>
          ))}
        </div>
      )}

      <Modal open={!!ratingModal} onClose={() => setRatingModal(null)} title="Avaliar Serviço">
        <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", marginBottom: 20 }}>Como foi sua experiência com o serviço?</p>
        <StarRating value={rating} onChange={setRating} />
        <div style={{ marginTop: 24 }}>
          <Btn onClick={handleRate} disabled={!rating} fullWidth>Enviar Avaliação</Btn>
        </div>
      </Modal>
    </div>
  );
}

// Admin Login
function AdminLogin({ onSuccess, toast }) {
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const ip = Security.getClientIP();

  const handle = async () => {
    if (!password) return;
    setLoading(true);
    try {
      const result = await Auth.adminLogin(password, ip);
      if (result.isNewIP) toast("⚠️ NOVO IP DETECTADO! Registrado no log.", "warning");
      toast("Acesso administrativo autorizado.", "success");
      onSuccess();
    } catch (e) { toast(e.message, "error"); }
    setLoading(false);
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 20, background: "#020810" }}>
      <Card style={{ maxWidth: 400, width: "100%", borderColor: "#ff444433" }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 48, marginBottom: 12 }}>🔐</div>
          <h2 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 24, fontWeight: 900, margin: "0 0 8px" }}>Área Restrita</h2>
          <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 13, margin: 0 }}>Acesso exclusivo para administrador</p>
        </div>
        <Field label="Senha Administrativa" type="password" value={password} onChange={setPassword} placeholder="••••••••••••" required icon="🔑" />
        <Btn onClick={handle} fullWidth loading={loading} variant="danger" size="lg">Acessar Painel</Btn>
        <div style={{ background: "#ff444408", border: "1px solid #ff444422", borderRadius: 8, padding: "10px 14px", marginTop: 16 }}>
          <p style={{ color: "#ff4444", fontFamily: "'Syne', sans-serif", fontSize: 11, margin: 0, lineHeight: 1.6 }}>
            ⚠️ Todas as tentativas de acesso são registradas. IPs desconhecidos serão alertados.
          </p>
        </div>
      </Card>
    </div>
  );
}

// Admin Panel
function AdminPanel({ toast, onExit }) {
  const [tab, setTab] = useState("requests");
  const [requests, setRequests] = useState([]);
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [config, setConfig] = useState({});
  const [selectedReq, setSelectedReq] = useState(null);
  const [statusNote, setStatusNote] = useState("");
  const [newStatus, setNewStatus] = useState("");
  const [filterStatus, setFilterStatus] = useState("Todos");

  const load = useCallback(() => {
    setRequests(RequestService.getAll());
    setUsers(DB.get("users") || []);
    setLogs(DB.get("access_logs") || []);
    setConfig(DB.get("site_config") || {});
  }, []);

  useEffect(() => { load(); }, [load]);

  const updateStatus = () => {
    if (!newStatus) { toast("Selecione um status.", "error"); return; }
    try {
      RequestService.updateStatus(selectedReq.id, newStatus, statusNote);
      toast("Status atualizado!", "success");
      setSelectedReq(null);
      load();
    } catch (e) { toast(e.message, "error"); }
  };

  const blockUser = (req) => {
    if (!confirm("Bloquear usuário e IP?")) return;
    RequestService.blockUser(req.userId, req.ip);
    toast("Usuário bloqueado!", "warning");
    load();
  };

  const saveConfig = () => {
    DB.set("site_config", config);
    toast("Configurações salvas!", "success");
  };

  const filtered = filterStatus === "Todos" ? requests : requests.filter(r => r.status === filterStatus);
  const stats = {
    total: requests.length,
    pendente: requests.filter(r => r.status === "Pendente").length,
    andamento: requests.filter(r => r.status === "Em andamento").length,
    finalizado: requests.filter(r => r.status === "Finalizado").length,
  };

  const tabs = [
    { id: "requests", label: "📋 Pedidos", badge: stats.pendente },
    { id: "users", label: "👥 Usuários" },
    { id: "logs", label: "🔒 Logs" },
    { id: "config", label: "⚙️ Config" },
  ];

  return (
    <div style={{ minHeight: "100vh", background: "#020810", padding: "20px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32, flexWrap: "wrap", gap: 16 }}>
        <div>
          <h1 style={{ fontFamily: "'Syne', sans-serif", fontSize: 28, fontWeight: 900, color: "#e6edf3", margin: "0 0 4px" }}>🛠️ Painel Admin</h1>
          <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 13, margin: 0 }}>CellConserto.PA — Área Administrativa</p>
        </div>
        <Btn onClick={() => { Auth.adminLogout(); onExit(); }} variant="ghost">Sair</Btn>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 16, marginBottom: 32 }}>
        {[
          { label: "Total", value: stats.total, icon: "📊", color: "#00b4d8" },
          { label: "Pendentes", value: stats.pendente, icon: "⏳", color: "#ffaa00" },
          { label: "Em Andamento", value: stats.andamento, icon: "🔧", color: "#00d68f" },
          { label: "Finalizados", value: stats.finalizado, icon: "✅", color: "#8b5cf6" },
        ].map((s, i) => (
          <Card key={i} style={{ textAlign: "center" }}>
            <div style={{ fontSize: 28, marginBottom: 8 }}>{s.icon}</div>
            <div style={{ color: s.color, fontFamily: "'Syne', sans-serif", fontSize: 32, fontWeight: 900 }}>{s.value}</div>
            <div style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 12, marginTop: 4 }}>{s.label}</div>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 8, marginBottom: 24, flexWrap: "wrap" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: "10px 20px", borderRadius: 10, border: `1px solid ${tab === t.id ? "#00d68f" : "#1e2a3a"}`,
            background: tab === t.id ? "#00d68f15" : "transparent",
            color: tab === t.id ? "#00d68f" : "#8892a4",
            fontFamily: "'Syne', sans-serif", fontSize: 13, fontWeight: 700, cursor: "pointer",
            display: "flex", alignItems: "center", gap: 6,
          }}>
            {t.label}
            {t.badge > 0 && <span style={{ background: "#ffaa00", color: "#000", borderRadius: 10, padding: "1px 7px", fontSize: 11, fontWeight: 900 }}>{t.badge}</span>}
          </button>
        ))}
      </div>

      {/* Requests Tab */}
      {tab === "requests" && (
        <div>
          <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
            {["Todos", "Pendente", "Aceito", "Recusado", "Em andamento", "Finalizado"].map(s => (
              <button key={s} onClick={() => setFilterStatus(s)} style={{
                padding: "6px 14px", borderRadius: 8, border: `1px solid ${filterStatus === s ? "#00d68f" : "#1e2a3a"}`,
                background: filterStatus === s ? "#00d68f15" : "transparent",
                color: filterStatus === s ? "#00d68f" : "#8892a4",
                fontFamily: "'Syne', sans-serif", fontSize: 12, fontWeight: 600, cursor: "pointer",
              }}>{s}</button>
            ))}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {filtered.map(r => {
              const user = users.find(u => u.id === r.userId);
              return (
                <Card key={r.id}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
                        <StatusBadge status={r.status} />
                        <span style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 12 }}>{new Date(r.createdAt).toLocaleString("pt-BR")}</span>
                      </div>
                      <h3 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 17, fontWeight: 700, margin: "0 0 4px" }}>
                        {r.brand} {r.model} — <span style={{ color: "#00b4d8" }}>{r.serviceType}</span>
                      </h3>
                      <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 13, margin: "0 0 6px" }}>
                        👤 {r.name} &nbsp;|&nbsp; 📞 {r.phone} &nbsp;|&nbsp; 🌐 {r.ip}
                      </p>
                      <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 13, margin: 0, lineHeight: 1.6 }}>{r.description}</p>
                      {r.adminNotes && <p style={{ color: "#00d68f", fontFamily: "'Syne', sans-serif", fontSize: 13, marginTop: 8 }}>📝 {r.adminNotes}</p>}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      <Btn onClick={() => { setSelectedReq(r); setNewStatus(r.status); setStatusNote(r.adminNotes || ""); }} size="sm" variant="outline">✏️ Gerenciar</Btn>
                      {!user?.blocked && <Btn onClick={() => blockUser(r)} size="sm" variant="danger">🚫 Bloquear</Btn>}
                    </div>
                  </div>
                </Card>
              );
            })}
            {filtered.length === 0 && (
              <Card style={{ textAlign: "center" }}>
                <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif" }}>Nenhum pedido encontrado.</p>
              </Card>
            )}
          </div>
        </div>
      )}

      {/* Users Tab */}
      {tab === "users" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {users.map(u => (
            <Card key={u.id}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
                <div>
                  <h3 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 16, fontWeight: 700, margin: "0 0 4px" }}>{u.name}</h3>
                  <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 13, margin: 0 }}>
                    📧 {u.email} &nbsp;|&nbsp; 📞 {u.phone} &nbsp;|&nbsp; 🌐 {u.registrationIP}
                  </p>
                  <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 12, margin: "4px 0 0" }}>
                    Cadastro: {new Date(u.createdAt).toLocaleDateString("pt-BR")}
                  </p>
                </div>
                {u.blocked ? (
                  <span style={{ background: "#ff444422", color: "#ff4444", padding: "4px 12px", borderRadius: 20, fontSize: 12, fontFamily: "'Syne', sans-serif", fontWeight: 700 }}>🚫 BLOQUEADO</span>
                ) : (
                  <Btn onClick={() => { RequestService.blockUser(u.id, u.registrationIP); load(); toast("Usuário bloqueado!", "warning"); }} size="sm" variant="danger">🚫 Bloquear</Btn>
                )}
              </div>
            </Card>
          ))}
          {users.length === 0 && <Card style={{ textAlign: "center" }}><p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif" }}>Nenhum usuário cadastrado.</p></Card>}
        </div>
      )}

      {/* Logs Tab */}
      {tab === "logs" && (
        <div>
          <div style={{ marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 18, margin: 0 }}>Log de Acessos ({logs.length})</h3>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {logs.map(l => (
              <Card key={l.id} style={{ padding: "12px 16px", borderColor: l.action.includes("FAILED") || l.action.includes("NEW_IP") || l.action.includes("RATE_LIMIT") ? "#ff444433" : "#1e2a3a" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ fontFamily: "monospace", background: "#1e2a3a", color: l.action.includes("FAILED") || l.action.includes("NEW") ? "#ff4444" : "#00d68f", padding: "3px 8px", borderRadius: 6, fontSize: 11, fontWeight: 700 }}>
                      {l.action}
                    </span>
                    <span style={{ color: "#8892a4", fontFamily: "monospace", fontSize: 12 }}>IP: {l.ip}</span>
                  </div>
                  <span style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 12 }}>
                    {new Date(l.timestamp).toLocaleString("pt-BR")}
                  </span>
                </div>
                {Object.keys(l.details).length > 0 && (
                  <p style={{ color: "#8892a4", fontFamily: "monospace", fontSize: 11, margin: "6px 0 0" }}>
                    {JSON.stringify(l.details)}
                  </p>
                )}
              </Card>
            ))}
            {logs.length === 0 && <Card style={{ textAlign: "center" }}><p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif" }}>Nenhum log registrado.</p></Card>}
          </div>
        </div>
      )}

      {/* Config Tab */}
      {tab === "config" && (
        <div style={{ maxWidth: 700 }}>
          <Card style={{ marginBottom: 24 }}>
            <h3 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 18, fontWeight: 700, marginBottom: 20 }}>📢 Banner de Aviso</h3>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
              <label style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 14, display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                <input type="checkbox" checked={config.bannerActive || false} onChange={e => setConfig(p => ({ ...p, bannerActive: e.target.checked }))} />
                Ativar banner
              </label>
            </div>
            <Field label="Texto do Banner" value={config.banner || ""} onChange={v => setConfig(p => ({ ...p, banner: v }))} placeholder="Ex: Atendemos apenas celulares Android." />
          </Card>
          <Card style={{ marginBottom: 24 }}>
            <h3 style={{ color: "#e6edf3", fontFamily: "'Syne', sans-serif", fontSize: 18, fontWeight: 700, marginBottom: 20 }}>🎨 Textos do Site</h3>
            <Field label="Título Principal" value={config.heroTitle || ""} onChange={v => setConfig(p => ({ ...p, heroTitle: v }))} placeholder="CellConserto.PA" />
            <Field label="Subtítulo" value={config.heroSubtitle || ""} onChange={v => setConfig(p => ({ ...p, heroSubtitle: v }))} placeholder="Especialistas em Android..." />
            <Field label="WhatsApp" value={config.whatsapp || ""} onChange={v => setConfig(p => ({ ...p, whatsapp: v }))} placeholder="+55 42 9153-3877" icon="💬" />
          </Card>
          <Btn onClick={saveConfig} size="lg">💾 Salvar Configurações</Btn>
        </div>
      )}

      {/* Manage Request Modal */}
      <Modal open={!!selectedReq} onClose={() => setSelectedReq(null)} title="Gerenciar Pedido">
        {selectedReq && (
          <div>
            <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 14, marginBottom: 20 }}>
              <strong style={{ color: "#e6edf3" }}>{selectedReq.brand} {selectedReq.model}</strong> — {selectedReq.name}
            </p>
            <div style={{ marginBottom: 20 }}>
              <label style={{ display: "block", color: "#8892a4", fontSize: 12, fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 8, fontFamily: "'Syne', sans-serif" }}>Novo Status</label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {["Pendente", "Aceito", "Recusado", "Em andamento", "Finalizado"].map(s => (
                  <button key={s} onClick={() => setNewStatus(s)} style={{
                    padding: "8px 14px", borderRadius: 8, border: `1px solid ${newStatus === s ? "#00d68f" : "#1e2a3a"}`,
                    background: newStatus === s ? "#00d68f15" : "transparent",
                    color: newStatus === s ? "#00d68f" : "#8892a4",
                    fontFamily: "'Syne', sans-serif", fontSize: 12, fontWeight: 600, cursor: "pointer",
                  }}>{s}</button>
                ))}
              </div>
            </div>
            <Field label="Nota para o Cliente" type="textarea" value={statusNote} onChange={setStatusNote} placeholder="Ex: Sua tela chegou e está em instalação..." />
            <div style={{ display: "flex", gap: 12 }}>
              <Btn onClick={updateStatus} fullWidth>Atualizar</Btn>
              <Btn onClick={() => setSelectedReq(null)} variant="ghost">Cancelar</Btn>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

// Profile Page
function ProfilePage({ currentUser, toast, onUpdate }) {
  const [form, setForm] = useState({ name: currentUser?.name || "", phone: currentUser?.phone || "" });
  const f = (field) => (val) => setForm(p => ({ ...p, [field]: val }));

  const save = () => {
    if (!Security.validatePhone(form.phone)) { toast("Telefone inválido.", "error"); return; }
    const users = DB.get("users") || [];
    const idx = users.findIndex(u => u.id === currentUser.id);
    if (idx === -1) return;
    users[idx].name = Security.sanitize(form.name);
    users[idx].phone = form.phone;
    DB.set("users", users);
    toast("Perfil atualizado!", "success");
    onUpdate(users[idx]);
  };

  return (
    <div style={{ padding: "60px 20px", maxWidth: 560, margin: "0 auto" }}>
      <h2 style={{ fontFamily: "'Syne', sans-serif", fontSize: 32, fontWeight: 900, color: "#e6edf3", marginBottom: 40 }}>Meu Perfil</h2>
      <Card>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ width: 80, height: 80, borderRadius: "50%", background: "linear-gradient(135deg, #00d68f, #00b4d8)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 12px", fontSize: 32 }}>
            {currentUser?.name?.[0]?.toUpperCase() || "?"}
          </div>
          <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 13, margin: 0 }}>{currentUser?.email}</p>
        </div>
        <Field label="Nome Completo" value={form.name} onChange={f("name")} icon="👤" />
        <Field label="Telefone" value={form.phone} onChange={f("phone")} mask="phone" icon="📞" />
        <Btn onClick={save} fullWidth>💾 Salvar</Btn>
      </Card>
    </div>
  );
}

// ============================================================
// APP
// ============================================================
export default function App() {
  const [page, setPage] = useState("home");
  const [currentUser, setCurrentUser] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [config, setConfig] = useState({});
  const { toasts, add: toast, remove } = useToast();

  useEffect(() => {
    DB.init();
    const user = Auth.getCurrentUser();
    if (user) setCurrentUser(user);
    const adminValid = Auth.isAdminValid();
    if (adminValid) setIsAdmin(true);
    setConfig(DB.get("site_config") || {});
  }, []);

  const navigate = (p) => setPage(p);

  const logout = () => {
    Auth.logout();
    setCurrentUser(null);
    setPage("home");
    toast("Até logo! 👋");
  };

  if (isAdmin) return (
    <>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800;900&display=swap'); * { margin: 0; padding: 0; box-sizing: border-box; } body { background: #020810; } @keyframes slideIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }`}</style>
      <AdminPanel toast={toast} onExit={() => { setIsAdmin(false); setPage("home"); }} />
      <Toast toasts={toasts} remove={remove} />
    </>
  );

  return (
    <>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800;900&display=swap'); * { margin: 0; padding: 0; box-sizing: border-box; } body { background: #020810; } @keyframes slideIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } } input:focus, textarea:focus { border-color: #00d68f !important; } button:hover { opacity: 0.9; transform: translateY(-1px); }`}</style>

      {/* Banner */}
      {config?.bannerActive && config?.banner && (
        <div style={{ background: "linear-gradient(90deg, #ffaa00, #ff7700)", color: "#000", textAlign: "center", padding: "10px 20px", fontFamily: "'Syne', sans-serif", fontSize: 14, fontWeight: 700 }}>
          📢 {config.banner}
        </div>
      )}

      {/* Nav */}
      <nav style={{ background: "#0d1117", borderBottom: "1px solid #1e2a3a", padding: "0 20px", position: "sticky", top: 0, zIndex: 100 }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center", height: 64 }}>
          <div onClick={() => navigate("home")} style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 24 }}>🔧</span>
            <span style={{ fontFamily: "'Syne', sans-serif", fontSize: 18, fontWeight: 900, color: "#e6edf3" }}>CellConserto<span style={{ color: "#00d68f" }}>.PA</span></span>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            {[
              { id: "home", label: "Início" },
              { id: "request", label: "Solicitar" },
              ...(currentUser ? [{ id: "dashboard", label: "Meus Pedidos" }, { id: "profile", label: "Perfil" }] : [{ id: "auth", label: "Entrar" }]),
            ].map(n => (
              <button key={n.id} onClick={() => navigate(n.id)} style={{
                padding: "8px 16px", borderRadius: 8, border: "none",
                background: page === n.id ? "#00d68f15" : "transparent",
                color: page === n.id ? "#00d68f" : "#8892a4",
                fontFamily: "'Syne', sans-serif", fontSize: 13, fontWeight: 600, cursor: "pointer",
              }}>{n.label}</button>
            ))}
            {currentUser && <Btn onClick={logout} variant="ghost" size="sm">Sair</Btn>}
            <Btn onClick={() => navigate("admin_login")} variant="ghost" size="sm">🔐</Btn>
          </div>
        </div>
      </nav>

      {/* Pages */}
      <main style={{ minHeight: "calc(100vh - 64px)" }}>
        {page === "home" && <LandingPage onNavigate={navigate} currentUser={currentUser} config={config} />}
        {page === "auth" && <AuthPage onSuccess={(u) => { setCurrentUser(u); navigate("dashboard"); }} toast={toast} />}
        {page === "request" && <RequestPage currentUser={currentUser} toast={toast} onNavigate={navigate} />}
        {page === "dashboard" && <DashboardPage currentUser={currentUser} toast={toast} />}
        {page === "profile" && <ProfilePage currentUser={currentUser} toast={toast} onUpdate={(u) => setCurrentUser(u)} />}
        {page === "admin_login" && <AdminLogin onSuccess={() => { setIsAdmin(true); setPage("admin"); }} toast={toast} />}
      </main>

      {/* Footer */}
      <footer style={{ background: "#0d1117", borderTop: "1px solid #1e2a3a", padding: "40px 20px", textAlign: "center" }}>
        <p style={{ color: "#8892a4", fontFamily: "'Syne', sans-serif", fontSize: 13 }}>
          © 2024 CellConserto.PA — Todos os direitos reservados &nbsp;|&nbsp; 📞 +55 42 9153-3877 &nbsp;|&nbsp; 📧 cell.consertos.pa@gmail.com
        </p>
      </footer>

      <Toast toasts={toasts} remove={remove} />
    </>
  );
}
