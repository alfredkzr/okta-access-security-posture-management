import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, Shield, ClipboardList, FileText, Settings, LogOut, User, Sun, Moon } from 'lucide-react';
import { cn } from '../lib/utils';
import { useAuth } from '../lib/auth';
import { useTheme } from '../lib/theme';

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
  const { theme, toggle } = useTheme();

  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-950">
      <aside className="w-64 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 flex flex-col">
        {/* Brand */}
        <div className="p-5 border-b border-gray-200 dark:border-gray-800">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-9 h-9 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center shadow-sm">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-gray-900 dark:text-gray-100 tracking-tight leading-tight">
                Okta Access
              </h1>
              <p className="text-[10px] font-medium text-gray-400 dark:text-gray-500 uppercase tracking-wider leading-tight">
                Security Posture
              </p>
            </div>
          </Link>
        </div>

        <nav className="flex-1 p-3 space-y-0.5">
          {nav.map(({ path, label, icon: Icon }) => {
            const active = path === '/' ? loc.pathname === '/' : loc.pathname.startsWith(path);
            return (
              <Link key={path} to={path} className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                active
                  ? 'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                  : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200'
              )}>
                <Icon className="w-4 h-4" />{label}
              </Link>
            );
          })}
        </nav>

        {/* User section */}
        {user && (
          <div className="p-3 border-t border-gray-200 dark:border-gray-800">
            <div className="flex items-center gap-3 px-3 py-2">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-indigo-500 rounded-full flex items-center justify-center">
                <User className="w-4 h-4 text-white" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">{user.name}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400 truncate">{user.email}</p>
              </div>
            </div>

            <button
              onClick={toggle}
              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200 transition-colors w-full mt-0.5"
            >
              {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
              {theme === 'light' ? 'Dark mode' : 'Light mode'}
            </button>

            <button
              onClick={logout}
              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200 transition-colors w-full"
            >
              <LogOut className="w-4 h-4" />
              Sign out
            </button>
          </div>
        )}
      </aside>
      <main className="flex-1 overflow-auto bg-gray-50 dark:bg-gray-950">
        <div className="p-8">{children}</div>
      </main>
    </div>
  );
}
