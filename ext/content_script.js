(() => {
    const br = chrome || browser;
    const s = document.createElement("script");
    const src = br.runtime.getURL("webauthn.js");
    //const bg = br.runtime.connect({'name': 'content-script'});
    const site = window.location.hostname;
    let pagePorts = {};

    s.setAttribute('src', src);
    s.setAttribute('id', "sphinx-webauthn-page-script");
    (document.head || document.documentElement).appendChild(s);

	window.addEventListener('message', webauthnEventHandler);

    br.runtime.onMessage.addListener((m) => {
        let port = pagePorts[m.results.id];
        port.postMessage(m.results);
        delete pagePorts[m.results.id];
    });

    function genId() {
        return Math.random().toString(32).slice(2) + Math.random().toString(32).slice(2);
    }

    function webauthnEventHandler(msg) {
        let options = msg.data;
        if(!options.type || options.type != "sphinxWebauthnEvent") {
            return;
        }
        if(msg.origin != window.origin) {
            console.log("invalid webauthnEvent sender");
            return;
        }
        const site = window.location.hostname;
        // TODO
        let bgMsg = {
            "site": site,
            "action": options.action,
            "params": options.params,
            "id": genId(),
        };
        pagePorts[bgMsg.id] = msg.ports[0];
        br.runtime.sendMessage(bgMsg);
        //br.runtime.sendMessage(bgMsg).then(
        //    function(response) {
        //        console.log('response received from bg', response);
        //        pagePort.postMessage(response);
        //    },
        //    function(error) {
        //        console.log('error received from bg', error);
        //        pagePort.postMessage(error);
        //    }
        //);
	}
})();

