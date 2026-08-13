import {
  ArchiveRestore,
  BookOpenCheck,
  EyeOff,
  FileWarning,
  Keyboard,
  KeyRound,
  ShieldCheck,
} from 'lucide-react';

import { Button, InlineNotice } from './ui';

export function HelpView({
  onOpenSettings,
  onOpenRecovery,
  onOpenBackups,
}: {
  onOpenSettings: () => void;
  onOpenRecovery: () => void;
  onOpenBackups: () => void;
}) {
  return (
    <section className="tool-view help-view" aria-labelledby="help-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <BookOpenCheck />
          </span>
          <div>
            <p className="eyebrow">Ohne Verbindung</p>
            <h1 id="help-title">Hilfe & Datenschutz</h1>
            <p>Diese Hilfe ist Teil von Kryptris und wird vollständig lokal angezeigt.</p>
          </div>
        </div>
      </header>

      <div className="help-view__sections">
        <section className="help-view__section" aria-labelledby="help-lock-title">
          <ShieldCheck aria-hidden="true" />
          <div>
            <h2 id="help-lock-title">Sicher arbeiten</h2>
            <p>
              Sperre Kryptris sofort, bevor du deinen Platz verlässt. Beim Sperren werden
              entschlüsselte Ansichten und laufende lokale Aufgaben beendet oder ungültig.
            </p>
            <ul>
              <li>Nutze ein langes, einzigartiges Master-Passwort.</li>
              <li>Prüfe die automatische Sperre und die Zwischenablage-Frist.</li>
              <li>Bewahre Wiederherstellungsschlüssel getrennt vom Gerät auf.</li>
            </ul>
          </div>
        </section>

        <section className="help-view__section" aria-labelledby="help-focus-title">
          <EyeOff aria-hidden="true" />
          <div>
            <h2 id="help-focus-title">Sichtschutz</h2>
            <p>
              Der Fokusmodus blendet in Listen Zusatztexte, Tags und Vorschau-Aktionen aus. Er
              reduziert sichtbare Informationen, verschlüsselt den geöffneten Tresor aber nicht
              zusätzlich.
            </p>
            <p>
              Der Windows-Inhaltsschutz kann Bildschirmaufnahmen erschweren. Er verhindert keine
              Aufnahme durch jede Software oder ein anderes Gerät.
            </p>
          </div>
        </section>

        <section className="help-view__section" aria-labelledby="help-recovery-title">
          <KeyRound aria-hidden="true" />
          <div>
            <h2 id="help-recovery-title">Wiederherstellung</h2>
            <p>
              Richte einen Wiederherstellungsschlüssel ein, solange du den Tresor sicher öffnen
              kannst. Er ist ein separater Zugang und ersetzt kein Master-Passwort.
            </p>
            <p>
              Öffne „Wiederherstellung“, wähle „Einrichten“ oder „Ersetzen“ und bewahre den neuen
              Schlüssel einmalig und getrennt vom Gerät auf. Teile ihn mit niemandem.
            </p>
          </div>
        </section>

        <section className="help-view__section" aria-labelledby="help-backup-title">
          <ArchiveRestore aria-hidden="true" />
          <div>
            <h2 id="help-backup-title">Backups & Wiederherstellung</h2>
            <p>
              Prüfe regelmäßig, ob ein aktuelles verschlüsseltes Backup vorhanden und lesbar ist.
              Ein Backup schützt nicht vor einem vergessenen Master-Passwort ohne gültigen
              Wiederherstellungsweg.
            </p>
            <p>
              Stelle nur aus einem erwarteten Backup wieder her und kontrolliere danach die
              Einträge. Bei endgültig gelöschten Papierkorb-Einträgen hilft nur ein zuvor erstelltes
              Backup.
            </p>
          </div>
        </section>

        <section className="help-view__section" aria-labelledby="help-factors-title">
          <ShieldCheck aria-hidden="true" />
          <div>
            <h2 id="help-factors-title">Zusätzliche Faktoren</h2>
            <p>
              TOTP und kompatible Sicherheitsschlüssel können den Zugang zusätzlich absichern. Halte
              mindestens einen unabhängigen Wiederherstellungsweg bereit, bevor du einen Faktor
              entfernst oder ersetzt.
            </p>
          </div>
        </section>

        <section className="help-view__section" aria-labelledby="help-export-title">
          <FileWarning aria-hidden="true" />
          <div>
            <h2 id="help-export-title">Klartext-Exporte sind riskant</h2>
            <p>
              CSV- und ähnliche Klartext-Exporte können Geheimnisse ohne Tresorverschlüsselung
              enthalten. Erstelle sie nur, wenn nötig, auf einem vertrauenswürdigen lokalen Ziel.
            </p>
            <p>
              Öffne sie nicht in synchronisierten Diensten, Messenger-Anhängen oder ungeschützten
              Tabellen und lösche sie anschließend sicher. Bevorzuge das verschlüsselte
              Kryptris-Backup, wenn kein Klartextformat erforderlich ist.
            </p>
          </div>
        </section>

        <section className="help-view__section" aria-labelledby="help-shortcuts-title">
          <Keyboard aria-hidden="true" />
          <div>
            <h2 id="help-shortcuts-title">Tastatur</h2>
            <dl className="help-view__shortcuts">
              <div>
                <dt>Strg + F</dt>
                <dd>Tresor durchsuchen</dd>
              </div>
              <div>
                <dt>Strg + K</dt>
                <dd>Befehlspalette öffnen</dd>
              </div>
              <div>
                <dt>Strg + L</dt>
                <dd>Kryptris sofort sperren</dd>
              </div>
              <div>
                <dt>Esc</dt>
                <dd>Offene Auswahl oder Navigation schließen</dd>
              </div>
            </dl>
          </div>
        </section>
      </div>

      <InlineNotice kind="info" title="Offline-Zusage">
        Kryptris lädt aus dieser Hilfe keine Bilder, Links oder Inhalte nach. Es werden keine
        Telemetriedaten übertragen.
      </InlineNotice>
      <div className="card-actions">
        <Button onClick={onOpenSettings}>Windows & Sichtschutz öffnen</Button>
        <Button variant="secondary" onClick={onOpenRecovery}>
          Wiederherstellung öffnen
        </Button>
        <Button variant="secondary" onClick={onOpenBackups}>
          Backups öffnen
        </Button>
      </div>
    </section>
  );
}
