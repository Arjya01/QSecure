import { create } from 'zustand';

const useAuthStore = create((set) => ({
  user: JSON.parse(localStorage.getItem('qsecure_user') || 'null'),
  accessToken: localStorage.getItem('qsecure_access') || null,
  refreshToken: localStorage.getItem('qsecure_refresh') || null,
  isAuthenticated: !!localStorage.getItem('qsecure_access'),

  setAuth: (user, accessToken, refreshToken) => {
    localStorage.setItem('qsecure_user', JSON.stringify(user));
    localStorage.setItem('qsecure_access', accessToken);
    localStorage.setItem('qsecure_refresh', refreshToken);
    set({ user, accessToken, refreshToken, isAuthenticated: !!accessToken });
  },

  setTokens: (accessToken, refreshToken) => {
    localStorage.setItem('qsecure_access', accessToken);
    if(refreshToken) localStorage.setItem('qsecure_refresh', refreshToken);
    set(state => ({ 
      accessToken, 
      refreshToken: refreshToken || state.refreshToken, 
      isAuthenticated: !!accessToken 
    }));
  },

  logout: () => {
    localStorage.removeItem('qsecure_user');
    localStorage.removeItem('qsecure_access');
    localStorage.removeItem('qsecure_refresh');
    set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false });
  }
}));

export default useAuthStore;
