(function () {
  const STORAGE_KEY = 'zbfox_cookie_consent_v1';
  const COOKIE_MAX_AGE_DAYS = 180;

  function getSavedConsent() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (error) {
      return null;
    }
  }

  function saveConsent(preferences) {
    const payload = {
      ...preferences,
      version: 1,
      timestamp: new Date().toISOString()
    };

    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    } catch (error) {
      // no-op: if storage is blocked, keep experience functional
    }

    const maxAge = COOKIE_MAX_AGE_DAYS * 24 * 60 * 60;
    document.cookie = `zbfox_cookie_preferences=${encodeURIComponent(JSON.stringify(payload))}; path=/; max-age=${maxAge}; samesite=lax`;
  }

  function createBanner() {
    const wrapper = document.createElement('section');
    wrapper.className = 'cookie-banner';
    wrapper.setAttribute('role', 'dialog');
    wrapper.setAttribute('aria-live', 'polite');
    wrapper.setAttribute('aria-label', 'Preferenze cookie');

    wrapper.innerHTML = `
      <p class="cookie-banner__eyebrow">PRIVACY E COOKIE</p>
      <h2>Gestisci i cookie del sito</h2>
      <p>
        Usiamo cookie tecnici necessari al funzionamento del sito. Con il tuo consenso possiamo usare anche cookie
        analytics e di personalizzazione. Puoi cambiare idea in qualsiasi momento dalla Cookie Policy.
      </p>
      <div class="cookie-banner__actions">
        <button type="button" class="btn btn-small" data-cookie-action="accept-all">Accetta tutti</button>
        <button type="button" class="btn btn-small btn-ghost" data-cookie-action="reject-optional">Rifiuta non necessari</button>
        <button type="button" class="btn btn-small btn-ghost" data-cookie-action="customize">Personalizza</button>
      </div>
      <p class="small cookie-banner__note">
        Dettagli completi nella <a href="cookie-policy.html">Cookie Policy</a>.
      </p>
    `;

    return wrapper;
  }

  function createPreferencesModal(onSave, onClose) {
    const modal = document.createElement('section');
    modal.className = 'cookie-modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-label', 'Personalizza cookie');

    modal.innerHTML = `
      <div class="cookie-modal__panel">
        <h2>Personalizza i cookie</h2>
        <p>Seleziona le categorie facoltative. I cookie tecnici restano sempre attivi.</p>

        <label class="cookie-toggle" for="cookie-necessary">
          <span>
            <strong>Tecnici necessari</strong>
            <small>Abilitati sempre: sicurezza, preferenze base e funzionamento.</small>
          </span>
          <input id="cookie-necessary" type="checkbox" checked disabled />
        </label>

        <label class="cookie-toggle" for="cookie-analytics">
          <span>
            <strong>Analytics</strong>
            <small>Misurazione del traffico in forma aggregata, dove possibile.</small>
          </span>
          <input id="cookie-analytics" type="checkbox" />
        </label>

        <label class="cookie-toggle" for="cookie-marketing">
          <span>
            <strong>Profilazione/Marketing</strong>
            <small>Personalizzazione contenuti e comunicazioni promozionali.</small>
          </span>
          <input id="cookie-marketing" type="checkbox" />
        </label>

        <div class="cookie-modal__actions">
          <button type="button" class="btn btn-small" data-cookie-modal="save">Salva preferenze</button>
          <button type="button" class="btn btn-small btn-ghost" data-cookie-modal="cancel">Annulla</button>
        </div>
      </div>
    `;

    const saveButton = modal.querySelector('[data-cookie-modal="save"]');
    const cancelButton = modal.querySelector('[data-cookie-modal="cancel"]');

    saveButton.addEventListener('click', () => {
      const analytics = Boolean(modal.querySelector('#cookie-analytics')?.checked);
      const marketing = Boolean(modal.querySelector('#cookie-marketing')?.checked);
      onSave({ necessary: true, analytics, marketing });
    });

    cancelButton.addEventListener('click', onClose);
    modal.addEventListener('click', (event) => {
      if (event.target === modal) {
        onClose();
      }
    });

    return modal;
  }

  function initConsentUi() {
    if (!document.body) {
      return;
    }

    if (getSavedConsent()) {
      return;
    }

    const banner = createBanner();
    document.body.appendChild(banner);

    let modal = null;

    function closeModal() {
      if (modal) {
        modal.remove();
        modal = null;
      }
    }

    function finalize(preferences) {
      saveConsent(preferences);
      closeModal();
      banner.remove();
    }

    banner.addEventListener('click', (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }

      const action = target.getAttribute('data-cookie-action');

      if (action === 'accept-all') {
        finalize({ necessary: true, analytics: true, marketing: true });
      }

      if (action === 'reject-optional') {
        finalize({ necessary: true, analytics: false, marketing: false });
      }

      if (action === 'customize') {
        if (!modal) {
          modal = createPreferencesModal(finalize, closeModal);
          document.body.appendChild(modal);
        }
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initConsentUi);
  } else {
    initConsentUi();
  }
})();
