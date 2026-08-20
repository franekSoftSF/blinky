import { Routes } from '@angular/router';
import { Dashboard } from './pages/dashboard';
import { Inventory } from './pages/inventory';
import { Settings } from './pages/settings';

export const routes: Routes = [
  { path: '', component: Dashboard },
  { path: 'tokens', component: Inventory, data: { kind: 'tokens' } },
  { path: 'certificates', component: Inventory, data: { kind: 'certificates' } },
  { path: 'agents', component: Inventory, data: { kind: 'agents' } },
  { path: 'jobs', component: Inventory, data: { kind: 'jobs' } },
  { path: 'settings', component: Settings },
  { path: '**', redirectTo: '' },
];
