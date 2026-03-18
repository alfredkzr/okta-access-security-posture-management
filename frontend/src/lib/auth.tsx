import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import api from './api';

interface User {
  sub: string;
  email: string;
  name: string;
  role: string;
  groups: string[];
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: () => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  login: () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if we have a session on mount
    api.get('/auth/me')
      .then(res => setUser(res.data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  function login() {
    // Redirect to backend login which redirects to Okta
    window.location.href = '/api/v1/auth/login';
  }

  async function logout() {
    try {
      await api.post('/auth/logout');
    } catch {
      // Ignore
    }
    setUser(null);
    window.location.href = '/';
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
