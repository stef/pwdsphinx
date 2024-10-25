(() => {
    const br = chrome || browser;
    const s = document.createElement("script");
    const src = br.runtime.getURL("webauthn.js");
    const bg = br.runtime.connect();
    const site = window.location.hostname;

    s.setAttribute('src', src);
    s.setAttribute('id', "sphinx-webauthn-page-script");
    (document.head || document.documentElement).appendChild(s);
	window.addEventListener('message', webauthnEventHandler);

    function webauthnEventHandler(msg) {
        console.log("MSGRECV", msg);
        let options = msg.data;
        if(!options.type || options.type != "sphinxWebauthnEvent") {
            return;
        }
        if(msg.origin != window.origin) {
            console.log("invalid webauthnEvent sender");
            return;
        }
        console.log("MSG DBG", msg, options);
        const site = window.location.hostname;
        // TODO
        let response = {
            "site": site,
            "action": options.action,
            "params": options.params,
        };
        //bg.postMessage();
        let pagePort = msg.ports[0];
        try {
            pagePort.postMessage(response);
        } catch(err) {
            console.log("Failed to send message to the page:", err);
        }
	}
})();

