const browserCredentials = {
  create: navigator.credentials.create.bind(
	navigator.credentials,
  ),
  get: navigator.credentials.get.bind(navigator.credentials),
};

navigator.credentials.create = async function(options) {
    if(!options && !options.publicKey) {
        // not webauthn call
        return await browserCredentials.create(options);
    }
    const pubKey = options.publicKey;
    const host = window.location.hostname;
    const response = await createEvent("create", {});
    console.log("CREATE RESP", response);
    const o_resp = await browserCredentials.create(options);
    console.log(o_resp);
    //return createCredentials(response);
};

navigator.credentials.get = async function(options) {
    if(!options && !options.publicKey) {
        // not webauthn call
        return await browserCredentials.get(options);
    }
    const pubKey = options.publicKey;
    const host = window.location.hostname;
    const response = await createEvent("get", {});
    console.log("GET RESP", response);
    //return createCredentials(response);
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

function createCredentials(res) {
     const credential = {
      id: res.id,
      rawId: stringToBuffer(res.id),
      type: "public-key",
      response: {
        authenticatorData: stringToBuffer(res.authenticatorData),
        clientDataJSON: stringToBuffer(res.clientDataJSON),
        signature: stringToBuffer(res.signature),
        userHandle: stringToBuffer(res.userHandle),
      },
      getClientExtensionress: () => ({}),
      authenticatorAttachment: "cross-platform",
    };
    Object.setPrototypeOf(credential.response, AuthenticatorAssertionResponse.prototype);
    Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
    return credential;
}

function stringToBuffer(s) {
	const str = atob(s);
	const bytes = new Uint8Array(str.length);
	for (let i = 0; i < str.length; i++) {
		bytes[i] = str.charCodeAt(i);
	}
	return bytes;
}
