import { Routes } from '@angular/router';
import { Dashboard } from './pages/dashboard';
import { Inventory } from './pages/inventory';
import { DirectoryDiagnostics } from './pages/settings';
import { OperatorSettings } from './pages/operator-settings';
import { Helpdesk } from './pages/helpdesk';
import { SystemStatusPage } from './pages/system-status';
import { SignIn } from './pages/sign-in';
import { signedIn } from './core/signed-in.guard';

export const routes: Routes = [
  // Outside the guard, for the obvious reason: signing in cannot require
  // being signed in.
  { path: 'sign-in', component: SignIn },

  { path: '', component: Dashboard, canActivate: [signedIn] },
  { path: 'tokens', component: Inventory, data: { kind: 'tokens' }, canActivate: [signedIn] },
  { path: 'tokens/:serial', component: Helpdesk, canActivate: [signedIn] },
  {
    path: 'certificates',
    component: Inventory,
    data: { kind: 'certificates' },
    canActivate: [signedIn],
  },
  { path: 'agents', component: Inventory, data: { kind: 'agents' }, canActivate: [signedIn] },
  { path: 'jobs', component: Inventory, data: { kind: 'jobs' }, canActivate: [signedIn] },
  { path: 'system', component: SystemStatusPage, canActivate: [signedIn] },
  { path: 'directory', component: DirectoryDiagnostics, canActivate: [signedIn] },
  { path: 'settings', component: OperatorSettings, canActivate: [signedIn] },
  { path: '**', redirectTo: '' },
];
