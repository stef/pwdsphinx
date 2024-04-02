(() => {
    const br = chrome || browser;
    const s = document.createElement("script");
    const src = br.runtime.getURL("webauthn.js");
    const bg = br.runtime.connect();
    const site = window.location.hostname;
    s.setAttribute('src', src);
    s.setAttribute('id', "sphinx-webauthn-page-script");
    (document.head || document.documentElement).appendChild(s);
	document.addEventListener('sphinxWebauthnEvent', function(event) {
        //console.log("new event", event);
        const port = event.detail.port;
        const site = window.location.hostname;
        const evType = event.detail.type;
        // TODO
        let user = '';
        let msg = { "action": "login", "site": site, "name": user, "mode": "insert" };
        if(evType == "register") {
            msg.action = "create";
        }
        chrome.runtime.sendMessage(
            msg,
            function(response) {
                port.postMessage(response);
            }
        );
        //bg.postMessage();
	});
})();
