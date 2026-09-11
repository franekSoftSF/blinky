import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthStore } from './auth.store';

/**
 * Nothing in the console is reachable without a session.
 *
 * This is a convenience and not a control: the guard runs in a browser, and
 * every endpoint behind it refuses on its own. What it buys is that somebody
 * who is not signed in sees a sign-in screen rather than a dashboard full of
 * failed requests - which is what the console did while the shared token was
 * the only way in and nobody had pasted one yet.
 */
export const signedIn: CanActivateFn = () => {
  const auth = inject(AuthStore);
  const router = inject(Router);

  return auth.signedIn() ? true : router.createUrlTree(['/sign-in']);
};
