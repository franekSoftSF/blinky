import { TestBed } from '@angular/core/testing';
import { App } from './app';
import { AuthStore } from './core/auth.store';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

describe('App', () => {
  beforeEach(async () => {
    // Nothing signed in unless a test says so: sessionStorage survives between
    // cases in the same environment, and a leftover token would make the shell
    // appear in the test that exists to prove it does not.
    sessionStorage.clear();

    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  /**
   * Somebody who is not signed in gets the sign-in page and nothing around it.
   *
   * This used to render the whole navigation tree with a sign-in form inside
   * it: a menu of pages the visitor cannot open, in front of the one thing
   * they can do.
   */
  it('draws no console shell before anybody signs in', async () => {
    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;

    expect(compiled.querySelector('.app-shell')).toBeNull();
    expect(compiled.querySelector('.brand strong')).toBeNull();
  });

  it('should render the product name once signed in', async () => {
    const auth = TestBed.inject(AuthStore);
    sessionStorage.setItem('blinky.session', 'a-session-token');
    (auth as unknown as { token: { set(value: string): void } }).token.set('a-session-token');

    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.brand strong')?.textContent).toContain('Blinky');
  });
});
