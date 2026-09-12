import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { currentUser, isAuthed, login as apiLogin, logout as apiLogout, register as apiRegister, User } from '../lib/api';

type AuthContextValue = { user: User | null; loading: boolean; login: (email: string, password: string) => Promise<void>; register: (data: { name: string; email: string; password: string; role: string }) => Promise<void>; logout: () => void };
const AuthContext = createContext<AuthContextValue | undefined>(undefined);
export const useAuth = () => { const value = useContext(AuthContext); if (!value) throw new Error('useAuth must be used within AuthProvider'); return value; };

export const AuthProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [user, setUser] = useState<User | null>(currentUser());
  const [loading, setLoading] = useState(isAuthed() && !currentUser());
  useEffect(() => { const onUnauthorized = () => setUser(null); window.addEventListener('capstonehub:unauthorized', onUnauthorized); setLoading(false); return () => window.removeEventListener('capstonehub:unauthorized', onUnauthorized); }, []);
  const value = useMemo(() => ({ user, loading, login: async (email: string, password: string) => { const result = await apiLogin(email, password); setUser(result.user); }, register: async (data: { name: string; email: string; password: string; role: string }) => { const result = await apiRegister(data); setUser(result.user); }, logout: () => { apiLogout(); setUser(null); } }), [user, loading]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
