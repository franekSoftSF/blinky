import { Routes } from '@angular/router';
import { Dashboard } from './pages/dashboard';
import { Inventory } from './pages/inventory';
import { DirectoryDiagnostics } from './pages/settings';
import { OperatorSettings } from './pages/operator-settings';
import { Helpdesk } from './pages/helpdesk';
import { SystemStatusPage } from './pages/system-status';

export const routes: Routes = [
  { path: '', component: Dashboard },
  { path: 'tokens', component: Inventory, data: { kind: 'tokens' } },
  { path: 'tokens/:serial', component: Helpdesk },
  { path: 'certificates', component: Inventory, data: { kind: 'certificates' } },
  { path: 'agents', component: Inventory, data: { kind: 'agents' } },
  { path: 'jobs', component: Inventory, data: { kind: 'jobs' } },
  { path: 'system', component: SystemStatusPage },
  { path: 'directory', component: DirectoryDiagnostics },
  { path: 'settings', component: OperatorSettings },
  { path: '**', redirectTo: '' },
];
