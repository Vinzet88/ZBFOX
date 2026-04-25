(function () {
  var STORAGE_KEY = 'zbfox_cookie_consent_v1';
  var COOKIE_NAME = 'zbfox_cookie_preferences';
  var COOKIE_MAX_AGE_DAYS = 180;

  function safeParse(raw) {
    try {
      return JSON.parse(raw);
    } catch (error) {
      return null;
    }
  }

  function getSavedConsent() {
    var fromStorage = null;

    try {
      fromStorage = localStorage.getItem(STORAGE_KEY);
    } catch (error) {
      fromStorage = null;
    }

    if (fromStorage) {
      return safeParse(fromStorage);
    }

    var cookies = document.cookie ? document.cookie.split('; ') : [];
    for (var i = 0; i < cookies.length; i += 1) {
      var pair = cookies[i].split('=');
      if (pair[0] === COOKIE_NAME && pair[1]) {
        return safeParse(decodeURIComponent(pair[1]));
      }
    }

    return null;
  }

  function saveConsent(preferences) {
    var payload = {
      necessary: true,
      analytics: !!preferences.analytics,
      marketing: !!preferences.marketing,
      version: 1,
      timestamp: new Date().toISOString()
    };

    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    } catch (error) {
      // localStorage might be blocked in private mode
    }

    var maxAge = COOKIE_MAX_AGE_DAYS * 24 * 60 * 60;
    document.cookie =
      COOKIE_NAME +
      '=' +
      encodeURIComponent(JSON.stringify(payload)) +
      '; path=/; max-age=' +
      maxAge +
      '; samesite=lax';

    return payload;
  }

  function removeNode(node) {
    if (node && node.parentNode) {
      node.parentNode.removeChild(node);
    }
  }

  function createBanner() {
    var wrapper = document.createElement('section');
    wrapper.className = 'cookie-banner';
    wrapper.setAttribute('role', 'dialog');
    wrapper.setAttribute('aria-live', 'polite');
    wrapper.setAttribute('aria-label', 'Preferenze cookie');

    wrapper.innerHTML =
      '<p class="cookie-banner__eyebrow">PRIVACY E COOKIE</p>' +
      '<h2>Gestisci i cookie del sito</h2>' +
      '<p>Usiamo cookie tecnici necessari al funzionamento del sito. Con il tuo consenso possiamo usare anche cookie analytics e di personalizzazione.</p>' +
      '<div class="cookie-banner__actions">' +
      '<button type="button" class="btn btn-small" data-cookie-action="accept-all">Accetta tutti</button>' +
      '<button type="button" class="btn btn-small btn-ghost" data-cookie-action="reject-optional">Rifiuta non necessari</button>' +
      '<button type="button" class="btn btn-small btn-ghost" data-cookie-action="customize">Personalizza</button>' +
      '</div>' +
      '<p class="small cookie-banner__note">Dettagli completi nella <a href="cookie-policy.html">Cookie Policy</a>.</p>';

    return wrapper;
  }

  function createPreferencesModal(onSave, onClose, currentConsent) {
    var modal = document.createElement('section');
    modal.className = 'cookie-modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-label', 'Personalizza cookie');

    modal.innerHTML =
      '<div class="cookie-modal__panel">' +
      '<h2>Personalizza i cookie</h2>' +
      '<p>Seleziona le categorie facoltative. I cookie tecnici restano sempre attivi.</p>' +
      '<label class="cookie-toggle" for="cookie-necessary">' +
      '<span><strong>Tecnici necessari</strong><small>Abilitati sempre: sicurezza, preferenze base e funzionamento.</small></span>' +
      '<input id="cookie-necessary" type="checkbox" checked disabled />' +
      '</label>' +
      '<label class="cookie-toggle" for="cookie-analytics">' +
      '<span><strong>Analytics</strong><small>Misurazione del traffico in forma aggregata, dove possibile.</small></span>' +
      '<input id="cookie-analytics" type="checkbox" />' +
      '</label>' +
      '<label class="cookie-toggle" for="cookie-marketing">' +
      '<span><strong>Profilazione/Marketing</strong><small>Personalizzazione contenuti e comunicazioni promozionali.</small></span>' +
      '<input id="cookie-marketing" type="checkbox" />' +
      '</label>' +
      '<div class="cookie-modal__actions">' +
      '<button type="button" class="btn btn-small" data-cookie-modal="save">Salva preferenze</button>' +
      '<button type="button" class="btn btn-small btn-ghost" data-cookie-modal="cancel">Annulla</button>' +
      '</div>' +
      '</div>';

    var analyticsInput = modal.querySelector('#cookie-analytics');
    var marketingInput = modal.querySelector('#cookie-marketing');

    if (currentConsent) {
      analyticsInput.checked = !!currentConsent.analytics;
      marketingInput.checked = !!currentConsent.marketing;
    }

    var saveButton = modal.querySelector('[data-cookie-modal="save"]');
    var cancelButton = modal.querySelector('[data-cookie-modal="cancel"]');

    saveButton.addEventListener('click', function () {
      onSave({
        analytics: analyticsInput.checked,
        marketing: marketingInput.checked
      });
    });

    cancelButton.addEventListener('click', onClose);
    modal.addEventListener('click', function (event) {
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

    var banner = null;
    var modal = null;

    function closeModal() {
      removeNode(modal);
      modal = null;
    }

    function openPreferences() {
      if (modal) {
        return;
      }
      modal = createPreferencesModal(
        function (preferences) {
          saveConsent(preferences);
          closeModal();
          removeNode(banner);
          banner = null;
        },
        closeModal,
        getSavedConsent()
      );
      document.body.appendChild(modal);
    }

    function bindPreferenceLinks() {
      var triggers = document.querySelectorAll('[data-cookie-open]');
      for (var i = 0; i < triggers.length; i += 1) {
        triggers[i].addEventListener('click', function (event) {
          event.preventDefault();
          openPreferences();
        });
      }
    }

    window.ZBFOXCookieConsent = {
      openPreferences: openPreferences
    };

    var existing = getSavedConsent();

    if (!existing) {
      banner = createBanner();
      document.body.appendChild(banner);
      banner.addEventListener('click', function (event) {
        var target = event.target;
        if (!target || !target.getAttribute) {
          return;
        }

        var action = target.getAttribute('data-cookie-action');
        if (action === 'accept-all') {
          saveConsent({ analytics: true, marketing: true });
          removeNode(banner);
          banner = null;
        } else if (action === 'reject-optional') {
          saveConsent({ analytics: false, marketing: false });
          removeNode(banner);
          banner = null;
        } else if (action === 'customize') {
          openPreferences();
        }
      });
    }

    bindPreferenceLinks();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initConsentUi);
  } else {
    initConsentUi();
  }
})();
