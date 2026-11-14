import { UI_STRINGS } from "../agentic/preferences";
import type { AppMode, Language, ThemeMode, UserPreferences } from "../types";

interface SettingsBarProps {
  preferences: UserPreferences;
  onChange: (next: UserPreferences) => void;
}

export function SettingsBar({ preferences, onChange }: SettingsBarProps): JSX.Element {
  const strings = UI_STRINGS[preferences.language];

  function setMode(mode: AppMode): void {
    onChange({ ...preferences, mode });
  }

  function setLanguage(language: Language): void {
    onChange({ ...preferences, language });
  }

  function setTheme(theme: ThemeMode): void {
    onChange({ ...preferences, theme });
  }

  return (
    <nav className="settings-bar" aria-label={strings.settingsLabel}>
      <div className="settings-bar__group" role="group" aria-label="Application Mode">
        <button
          type="button"
          className={`seg-btn${preferences.mode === "normal" ? " seg-btn--active" : ""}`}
          onClick={() => setMode("normal")}
          aria-pressed={preferences.mode === "normal"}
        >
          ● {strings.modeNormal}
        </button>
        <button
          type="button"
          className={`seg-btn${preferences.mode === "dev" ? " seg-btn--active" : ""}`}
          onClick={() => setMode("dev")}
          aria-pressed={preferences.mode === "dev"}
        >
          ⌘ {strings.modeDev}
        </button>
      </div>

      <div className="settings-bar__right">
        <div className="settings-bar__group" role="group" aria-label="Language">
          <button
            type="button"
            className={`seg-btn${preferences.language === "vi" ? " seg-btn--active" : ""}`}
            onClick={() => setLanguage("vi")}
            aria-pressed={preferences.language === "vi"}
          >
            VI
          </button>
          <button
            type="button"
            className={`seg-btn${preferences.language === "en" ? " seg-btn--active" : ""}`}
            onClick={() => setLanguage("en")}
            aria-pressed={preferences.language === "en"}
          >
            EN
          </button>
        </div>

        <div className="settings-bar__group" role="group" aria-label="Theme">
          <button
            type="button"
            className={`seg-btn${preferences.theme === "light" ? " seg-btn--active" : ""}`}
            onClick={() => setTheme("light")}
            aria-pressed={preferences.theme === "light"}
          >
            ○ {strings.themeLight}
          </button>
          <button
            type="button"
            className={`seg-btn${preferences.theme === "dark" ? " seg-btn--active" : ""}`}
            onClick={() => setTheme("dark")}
            aria-pressed={preferences.theme === "dark"}
          >
            ◐ {strings.themeDark}
          </button>
        </div>
      </div>
    </nav>
  );
}

