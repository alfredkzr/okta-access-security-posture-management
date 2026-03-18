import { Shield } from 'lucide-react';
import { useAuth } from '../lib/auth';

export default function Login() {
  const { login } = useAuth();

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex items-center justify-center">
      <div className="bg-white dark:bg-gray-900 rounded-xl shadow-sm border border-gray-200 dark:border-gray-800 p-10 w-full max-w-sm text-center">
        <div className="flex justify-center mb-6">
          <div className="w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center">
            <Shield className="w-8 h-8 text-white" />
          </div>
        </div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">Okta ASPM</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-8">Access Security Posture Management</p>
        <button
          onClick={login}
          className="w-full px-4 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors text-sm"
        >
          Sign in with Okta
        </button>
        <p className="text-xs text-gray-400 dark:text-gray-500 mt-6">
          You will be redirected to your Okta organization to sign in.
        </p>
      </div>
    </div>
  );
}
