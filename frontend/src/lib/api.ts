export const API_BASE = (import.meta as ImportMeta & { env: { VITE_API_URL?: string } }).env.VITE_API_URL || 'http://localhost:5001/api';

export type ApiResponse<T> = { success?: boolean; data?: T; message?: string; error?: string };

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('capstonehub_token');
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const body = (await response.json().catch(() => ({}))) as ApiResponse<T> & T;
  if (response.status === 401) {
    localStorage.removeItem('capstonehub_token');
    localStorage.removeItem('capstonehub_user');
    window.dispatchEvent(new Event('capstonehub:unauthorized'));
  }
  if (!response.ok) throw new Error(body.message || body.error || `Request failed (${response.status})`);
  return (body.data !== undefined ? body.data : body) as T;
}

export const get = <T,>(path: string) => api<T>(path);
export const post = <T,>(path: string, data?: unknown) => api<T>(path, { method: 'POST', body: data === undefined ? undefined : JSON.stringify(data) });
export const patch = <T,>(path: string, data?: unknown) => api<T>(path, { method: 'PATCH', body: data === undefined ? undefined : JSON.stringify(data) });
export const put = <T,>(path: string, data?: unknown) => api<T>(path, { method: 'PUT', body: data === undefined ? undefined : JSON.stringify(data) });
export const del = <T,>(path: string) => api<T>(path, { method: 'DELETE' });

export type Role = 'FACULTY' | 'TEAM_LEAD' | 'TEAM_MEMBER';
export type User = { id: string; name: string; email: string; role: Role };
export type Project = { id: string; name: string; description?: string; team?: { members?: User[] }; faculty?: User; _count?: Record<string, number>; [key: string]: unknown };
export type Requirement = { id: string; title: string; description?: string; type?: string; priority?: string; status?: string; [key: string]: unknown };
export type Story = { id: string; title: string; description?: string; priority?: string; storyPoints?: number; status?: string; order?: number; [key: string]: unknown };
export type Sprint = { id: string; name: string; status?: string; startDate?: string; endDate?: string; [key: string]: unknown };
export type Bug = { id: string; title: string; description?: string; priority?: string; severity?: string; status?: string; [key: string]: unknown };
export type Milestone = { id: string; title: string; description?: string; dueDate?: string; deliverables?: unknown[]; [key: string]: unknown };
export type Task = { id: string; title: string; status?: string; assignee?: User; [key: string]: unknown };

export function asList<T>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    for (const key of ['items', 'projects', 'requirements', 'stories', 'sprints', 'bugs', 'milestones', 'tasks', 'notifications', 'data']) {
      if (Array.isArray(record[key])) return record[key] as T[];
    }
  }
  return [];
}

export const formatDate = (value?: string) => value ? new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(value)) : '—';
export const initials = (name = '') => name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase() || 'CH';
export const tone = (value = '') => value.toLowerCase().replace(/_/g, ' ');

export async function login(email: string, password: string) {
  const result = await post<{ user: User; token: string }>('/auth/login', { email, password });
  localStorage.setItem('capstonehub_token', result.token);
  localStorage.setItem('capstonehub_user', JSON.stringify(result.user));
  return result;
}
export async function register(data: { name: string; email: string; password: string; role: string }) {
  const result = await post<{ user: User; token: string }>('/auth/register', data);
  localStorage.setItem('capstonehub_token', result.token);
  localStorage.setItem('capstonehub_user', JSON.stringify(result.user));
  return result;
}
export function logout() { localStorage.removeItem('capstonehub_token'); localStorage.removeItem('capstonehub_user'); }
export function currentUser(): User | null { try { return JSON.parse(localStorage.getItem('capstonehub_user') || 'null'); } catch { return null; } }
export function isAuthed() { return Boolean(localStorage.getItem('capstonehub_token')); }

export const endpoints = {
  projects: '/projects', requirements: (id: string) => `/projects/${id}/requirements`, stories: (id: string) => `/projects/${id}/stories`, backlog: (id: string) => `/projects/${id}/backlog`, sprints: (id: string) => `/projects/${id}/sprints`, bugs: (id: string) => `/projects/${id}/bugs`, milestones: (id: string) => `/projects/${id}/milestones`, deliverables: (id: string) => `/projects/${id}/deliverables`, traceability: (id: string) => `/projects/${id}/traceability/matrix`, activity: (id: string) => `/projects/${id}/activity`, members: (id: string) => `/projects/${id}/members`, github: (id: string) => `/projects/${id}/github`, faculty: '/faculty/dashboard', notifications: '/notifications', unread: '/notifications/unread-count', requirement: (id: string) => `/requirements/${id}`, requirementVersions: (id: string) => `/requirements/${id}/versions`, requirementStories: (id: string) => `/requirements/${id}/stories`, story: (id: string) => `/stories/${id}`, storyTasks: (id: string) => `/stories/${id}/tasks`, task: (id: string) => `/tasks/${id}`, sprint: (id: string) => `/sprints/${id}`, sprintBoard: (id: string) => `/sprints/${id}/board`, milestoneDeliverables: (id: string) => `/milestones/${id}/deliverables`, deliverable: (id: string) => `/deliverables/${id}`
};

export default api;
