import { HttpInterceptorFn } from '@angular/common/http';

/**
 * Every request carries the session cookie, and every state-changing one
 * carries the anti-CSRF token back.
 *
 * The session itself is a cookie this code cannot read (0101), so there is
 * nothing here to attach and nothing for an injected script to steal. What is
 * left is the other half of double-submit: the server sets a readable
 * `blinky_csrf` cookie, and a request that changes something has to echo it in
 * a header. A foreign page can make the browser send our cookies, but it
 * cannot read them, so it cannot produce this header.
 */
export const credentialsInterceptor: HttpInterceptorFn = (request, next) => {
  let headers = request.headers;

  if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
    const token = readCookie('blinky_csrf');

    if (token) {
      headers = headers.set('X-Blinky-Csrf', token);
    }
  }

  // withCredentials because the console and the API are the same origin behind
  // the edge, but not while `ng serve` proxies them - and a cookie dropped in
  // development is a defect found only in production.
  return next(request.clone({ withCredentials: true, headers }));
};

export function readCookie(name: string): string | null {
  const match = document.cookie
    .split('; ')
    .find((entry) => entry.startsWith(`${name}=`));

  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}
