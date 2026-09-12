import React from 'react';
import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom';
import { Layout } from './components/Layout';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AuthPage } from './pages/AuthPage';
import { DashboardPage } from './pages/DashboardPage';
import { ProjectsPage } from './pages/ProjectsPage';
import { ProjectWorkspacePage } from './pages/ProjectWorkspacePage';
import { FacultyPage } from './pages/FacultyPage';

const RequireAuth: React.FC = () => { const { user, loading } = useAuth(); const location = useLocation(); if (loading) return <div className="flex min-h-screen items-center justify-center text-sm text-slate-500">Loading your workspace…</div>; return user ? <Outlet/> : <Navigate to={`/login?next=${encodeURIComponent(location.pathname)}`} replace/>; };
const RequireFaculty: React.FC = () => { const { user } = useAuth(); return user?.role === 'FACULTY' ? <Outlet/> : <Navigate to="/dashboard" replace/>; };
const RedirectAuthed: React.FC = () => { const { user } = useAuth(); return user ? <Navigate to={user.role === 'FACULTY' ? '/faculty/dashboard' : '/dashboard'} replace/> : <Outlet/>; };
export const App: React.FC = () => <BrowserRouter><AuthProvider><Routes><Route element={<RedirectAuthed/>}><Route path="/login" element={<AuthPage/>}/><Route path="/register" element={<AuthPage/>}/></Route><Route element={<RequireAuth/>}><Route element={<Layout/>}><Route path="/dashboard" element={<DashboardPage/>}/><Route path="/projects" element={<ProjectsPage/>}/><Route path="/projects/:projectId" element={<ProjectWorkspacePage/>}/><Route path="/faculty" element={<RequireFaculty/>}><Route path="dashboard" element={<FacultyPage/>}/></Route><Route path="/notifications" element={<NotificationsPlaceholder/>}/><Route path="*" element={<Navigate to="/dashboard" replace/>}/></Route></Route></Routes></AuthProvider></BrowserRouter>;
const NotificationsPlaceholder = () => <div className="surface p-10"><p className="eyebrow">Updates</p><h1 className="mt-2 text-2xl font-semibold">Notifications</h1><p className="mt-2 text-sm text-slate-500">Notification feed is available through the backend; connect it to your review workflow from here.</p></div>;
export default App;
