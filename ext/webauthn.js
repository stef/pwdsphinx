const browserCredentials = {
  create: navigator.credentials.create.bind(
	navigator.credentials,
  ),
  get: navigator.credentials.get.bind(navigator.credentials),
};

navigator.credentials.create = function(options) {
    if(!options && !options.publicKey) {
        // not webauthn call
        return await browserCredentials.create(options)
    }
    const pubKey = options.publicKey;
    const host = window.location.hostname;
    const response = await createEvent("create", {});
    console.log("CREATE RESP", response);
};

navigator.credentials.get = async function(options) {
    if(!options && !options.publicKey) {
        // not webauthn call
        return await browserCredentials.get(options)
    }
    const pubKey = options.publicKey;
    const host = window.location.hostname;
    const response = await createEvent("get", {});
    console.log("GET RESP", response);
};

async function createEvent(evType, params) {
    const { port1: localPort, port2: remotePort } = new MessageChannel();
    let ev = new CustomEvent("sphinxWebauthnEvent", {
        "detail": {
            "type": evType,
            "port": remotePort,
            "params": params,
        }
    });
    document.dispatchEvent(ev);
	const promise = new Promise((resolve) => {
		localPort.onmessage = (event) => resolve(event.data);
	});
    return await promise
}
