import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { OperatorSettings } from './operator-settings';

describe('operator settings', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      imports: [OperatorSettings],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }),
  );
  it('uses an in-page action instead of submitting a navigation form', () => {
    const fixture = TestBed.createComponent(OperatorSettings);
    fixture.detectChanges();
    const button = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
    expect(button.type).toBe('button');
    expect(fixture.nativeElement.querySelector('form')).toBeNull();
  });
});
