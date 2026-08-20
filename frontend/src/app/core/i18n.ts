import { Injectable, computed, signal } from '@angular/core';

type Language = 'pl' | 'en';
const messages = {
  pl: {
    overview:'Przegląd',tokens:'Tokeny',certificates:'Certyfikaty',agents:'Agenci',jobs:'Zadania',settings:'Ustawienia',
    subtitle:'Centrum zarządzania poświadczeniami PIV',apiOnline:'API online',apiOffline:'API offline',local:'Środowisko lokalne',refresh:'Odśwież',operator:'Operator',administrator:'Administrator',
    environmentState:'STAN ŚRODOWISKA',hello:'Dzień dobry.',helloText:'Najważniejsze informacje o tokenach i certyfikatach w jednym miejscu.',refreshData:'Odśwież dane',
    noApi:'Brak danych z API',noApiText:'Podaj token operatora w Ustawieniach albo sprawdź połączenie.',active:'aktywnych',expiresSoon:'wygasa wkrótce',registered:'zarejestrowanych',runningJobs:'Zadania w toku',queue:'kolejka operacji',
    recentJobs:'Ostatnie zadania',sentOperations:'Operacje wysłane do agentów',all:'Zobacz wszystkie',operation:'Operacja',token:'Token',status:'Status',created:'Utworzono',noJobs:'Brak ostatnich zadań',newJobsHere:'Nowe operacje pojawią się tutaj.',
    serviceHealth:'Kondycja usług',platformComponents:'Komponenty platformy',managementApi:'Interfejs zarządzający',works:'Działa',noConnection:'Brak połączenia',ca:'Urząd certyfikacji',builtinPki:'Wbudowany backend PKI',configured:'Skonfigurowany',stateHistory:'Stan i historia operacji',throughApi:'Przez API',
    inventory:'INWENTARZ',pivTokens:'Tokeny PIV',tokensText:'Sprzęt wykryty i zarządzany przez Blinky.',certsText:'Poświadczenia wystawione i zapisane na tokenach.',agentsTitle:'Agenci stacji',agentsText:'Stacje robocze połączone z usługą.',jobsText:'Historia i bieżący przebieg operacji.',search:'Szukaj…',newOperation:'Nowa operacja',noData:'Brak danych',noDataText:'Po połączeniu z API obiekty pojawią się w tym widoku.',
    serial:'Numer seryjny',model:'Model',firmware:'Firmware',pin:'PIN',subject:'Podmiot',tokenSlot:'Token / slot',validTo:'Ważny do',hostname:'Nazwa stacji',domain:'Domena',version:'Wersja',lastSeen:'Ostatnio widziany',attempt:'Próba',
    configuration:'KONFIGURACJA',consoleSettings:'Ustawienia Blinky CMS',settingsText:'Dane sesji operatora i informacje o połączeniu.',operatorAccess:'Dostęp operatora',operatorHelp:'Token jest przechowywany wyłącznie w pamięci sesji przeglądarki. Zamknięcie karty go usuwa.',operatorToken:'Token operatora',enterToken:'Wprowadź token…',saveConnect:'Zapisz i połącz',about:'O aplikacji',aboutText:'Blinky CMS · Angular 22 · połączenie z API przez ten sam origin.',openSource:'Open source',language:'Język',credentialConsole:'Zarządzanie PIV',actions:'Akcje',recycle:'Wycofaj i wyczyść slot',recycleConfirm:'Certyfikat zostanie wycofany, a agent usunie certyfikat i klucz prywatny ze slotu. Kontynuować?',jobQueued:'Zadanie wycofania zostało dodane do kolejki.',operationFailed:'Nie udało się utworzyć zadania.',lightTheme:'Włącz jasny motyw',darkTheme:'Włącz ciemny motyw'
  },
  en: {
    overview:'Overview',tokens:'Tokens',certificates:'Certificates',agents:'Agents',jobs:'Jobs',settings:'Settings',
    subtitle:'PIV credential management center',apiOnline:'API online',apiOffline:'API offline',local:'Local environment',refresh:'Refresh',operator:'Operator',administrator:'Administrator',
    environmentState:'ENVIRONMENT STATUS',hello:'Good morning.',helloText:'Your tokens and certificates at a glance.',refreshData:'Refresh data',
    noApi:'API data unavailable',noApiText:'Enter the operator token in Settings or verify the connection.',active:'active',expiresSoon:'expiring soon',registered:'registered',runningJobs:'Jobs in progress',queue:'operation queue',
    recentJobs:'Recent jobs',sentOperations:'Operations sent to agents',all:'View all',operation:'Operation',token:'Token',status:'Status',created:'Created',noJobs:'No recent jobs',newJobsHere:'New operations will appear here.',
    serviceHealth:'Service health',platformComponents:'Platform components',managementApi:'Management interface',works:'Healthy',noConnection:'No connection',ca:'Certificate authority',builtinPki:'Built-in PKI backend',configured:'Configured',stateHistory:'State and operation history',throughApi:'Via API',
    inventory:'INVENTORY',pivTokens:'PIV tokens',tokensText:'Hardware detected and managed by Blinky.',certsText:'Credentials issued and installed on tokens.',agentsTitle:'Workstation agents',agentsText:'Workstations connected to the service.',jobsText:'Operation history and current progress.',search:'Search…',newOperation:'New operation',noData:'No data',noDataText:'Objects will appear here after connecting to the API.',
    serial:'Serial number',model:'Model',firmware:'Firmware',pin:'PIN',subject:'Subject',tokenSlot:'Token / slot',validTo:'Valid until',hostname:'Hostname',domain:'Domain',version:'Version',lastSeen:'Last seen',attempt:'Attempt',
    configuration:'CONFIGURATION',consoleSettings:'Blinky CMS settings',settingsText:'Operator session data and connection information.',operatorAccess:'Operator access',operatorHelp:'The token is stored only in browser session memory. Closing the tab removes it.',operatorToken:'Operator token',enterToken:'Enter token…',saveConnect:'Save and connect',about:'About',aboutText:'Blinky CMS · Angular 22 · same-origin API connection.',openSource:'Open source',language:'Language',credentialConsole:'PIV management',actions:'Actions',recycle:'Withdraw and recycle slot',recycleConfirm:'The credential will be withdrawn and the agent will remove its certificate and private key from the slot. Continue?',jobQueued:'The withdrawal job was queued.',operationFailed:'The job could not be created.',lightTheme:'Use light theme',darkTheme:'Use dark theme'
  }
} as const;
export type MessageKey = keyof typeof messages.pl;

@Injectable({ providedIn:'root' })
export class I18n {
  readonly language=signal<Language>((localStorage.getItem('blinky.language') as Language)==='en'?'en':'pl');
  readonly locale=computed(()=>this.language()==='pl'?'pl-PL':'en-GB');
  t(key:MessageKey):string { return messages[this.language()][key]; }
  use(language:Language):void { this.language.set(language); localStorage.setItem('blinky.language',language); document.documentElement.lang=language; }
  toggle():void { this.use(this.language()==='pl'?'en':'pl'); }
}
