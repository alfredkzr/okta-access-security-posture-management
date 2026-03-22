import { Shield } from 'lucide-react';
import { useAuth } from '../lib/auth';

export default function Login() {
  const { login } = useAuth();

  return (
    <div className="min-h-screen bg-bg-base flex items-center justify-center relative overflow-hidden">
      {/* Ambient glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-500/[0.04] rounded-full blur-3xl pointer-events-none" />

      <div className="glass-panel-glow p-10 w-full max-w-sm text-center relative z-10">
        <div className="flex justify-center mb-6">
          <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-blue-700 rounded-2xl flex items-center justify-center shadow-lg shadow-blue-500/25">
            <Shield className="w-8 h-8 text-white" />
          </div>
        </div>
        <h1 className="text-2xl font-bold text-text-primary mb-1">Access Security</h1>
        <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-8">Posture Management</p>
        <button
          onClick={login}
          className="w-full px-4 py-3 bg-gradient-to-r from-blue-600 to-blue-500 text-white font-medium rounded-lg hover:from-blue-500 hover:to-blue-400 transition-all text-sm shadow-lg shadow-blue-500/20"
        >
          Sign in with Okta
        </button>
        <p className="text-xs text-text-muted mt-6">
          You will be redirected to your Okta organization to sign in.
        </p>
      </div>
    </div>
  );
}
