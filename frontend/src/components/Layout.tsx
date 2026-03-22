import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, Shield, ClipboardList, FileText, Settings, LogOut, ExternalLink } from 'lucide-react';
import { cn } from '../lib/utils';
import { useAuth } from '../lib/auth';

const nav = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Shield },
  { path: '/scenarios', label: 'Scenarios', icon: ClipboardList },
  { path: '/reports', label: 'Reports', icon: FileText },
  { path: '/settings', label: 'Settings', icon: Settings },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const loc = useLocation();
  const { user, logout } = useAuth();

  return (
    <div className="flex h-screen bg-bg-base">
      <aside className="w-64 glass-sidebar flex flex-col shrink-0">
        {/* Brand */}
        <div className="p-5 border-b border-border-glass">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-9 h-9 bg-gradient-to-br from-blue-500 to-blue-700 rounded-lg flex items-center justify-center shadow-lg shadow-blue-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-text-primary tracking-tight leading-tight">
                Access Security
              </h1>
              <p className="text-[10px] font-medium text-text-muted uppercase tracking-wider leading-tight">
                Posture Management
              </p>
            </div>
          </Link>
        </div>

        <nav className="flex-1 p-3 space-y-0.5">
          {nav.map(({ path, label, icon: Icon }) => {
            const active = path === '/' ? loc.pathname === '/' : loc.pathname.startsWith(path);
            return (
              <Link key={path} to={path} className={cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200',
                active
                  ? 'bg-accent-glow text-blue-400 shadow-sm shadow-blue-500/10 border border-blue-500/20'
                  : 'text-text-secondary hover:text-text-primary hover:bg-white/[0.03] border border-transparent'
              )}>
                <Icon className={cn('w-[18px] h-[18px]', active && 'text-blue-400')} />{label}
              </Link>
            );
          })}
        </nav>

        {/* User section */}
        {user && (
          <div className="p-3 border-t border-border-glass">
            <div className="flex items-center gap-3 px-3 py-2">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500/20 to-indigo-500/20 border border-blue-500/20 flex items-center justify-center">
                <span className="text-xs font-semibold text-blue-400">
                  {user.name?.charAt(0)?.toUpperCase() || user.email?.charAt(0)?.toUpperCase() || '?'}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-text-primary truncate">{user.name}</p>
                <p className="text-xs text-text-muted truncate">{user.email}</p>
              </div>
            </div>

            <button
              onClick={logout}
              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-white/[0.03] transition-colors w-full mt-0.5"
            >
              <LogOut className="w-4 h-4" />
              Sign out
            </button>
          </div>
        )}

        {/* Watermark */}
        <div className="px-5 py-3 border-t border-border-glass">
          <a
            href="https://github.com/alfredkzr"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-[10px] text-text-muted hover:text-text-secondary transition-colors"
          >
            Built by Alfred Koh
            <ExternalLink className="w-2.5 h-2.5" />
          </a>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <div className="p-8">{children}</div>
      </main>
    </div>
  );
}
