(() => {
    const s = document.createElement("script");
    const src = chrome.runtime.getURL("webauthn.js");
    s.setAttribute('src', src);
    s.setAttribute('id', "sphinx-webauthn-page-script");
    (document.head || document.documentElement).appendChild(s);
})();
