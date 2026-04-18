import { create } from 'zustand';
import { defaultScope } from '../utils/scope';

const useDomainStore = create((set) => ({
  activeScope: JSON.parse(localStorage.getItem('qsecure_scope') || 'null') || defaultScope,
  setActiveScope: (scope) => {
    const nextScope = scope || defaultScope;
    localStorage.setItem('qsecure_scope', JSON.stringify(nextScope));
    set({ activeScope: nextScope });
  },
}));

export default useDomainStore;
