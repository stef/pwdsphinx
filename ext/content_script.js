(() => {
    const br = chrome || browser;
    const s = document.createElement("script");
    const src = br.runtime.getURL("webauthn.js");
    const bg = br.runtime.connect();
    const site = window.location.hostname;

    s.setAttribute('src', src);
    s.setAttribute('id', "sphinx-webauthn-page-script");
    (document.head || document.documentElement).appendChild(s);
	document.addEventListener('sphinxWebauthnEvent', webauthnEventHandler);

    function webauthnEventHandler(event) {
        if(event.source != window) {
            console.log("invalid webauthnEvent sender", window.source);
            return;
        }
        console.log("MSG DBG", event.data);
        const port = event.port;
        const site = window.location.hostname;
        const evType = event.type;
        // TODO
        let msg = {
            "site": site,
            "action": event.type,
            "params": event.params,
        };
        chrome.runtime.sendMessage(
            msg,
            function(response) {
                port.postMessage(response);
            }
        );
        //bg.postMessage();
	}
})();

