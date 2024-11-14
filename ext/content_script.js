(() => {
    const br = chrome || browser;
    const s = document.createElement("script");
    const src = br.runtime.getURL("webauthn.js");
    //const bg = br.runtime.connect();
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
        let bgMsg = {
            "site": site,
            "action": options.action,
            "params": options.params,
        };
        let pagePort = msg.ports[0];
        br.runtime.sendMessage(bgMsg).then(
            function(response) {
                console.log('response received from native app', response);
                pagePort.postMessage(response);
            },
            function(error) {
                console.log('error received from native app', error);
                pagePort.postMessage(error);
            }
        );
	}
})();

