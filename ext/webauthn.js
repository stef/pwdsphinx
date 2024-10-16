// save original credential functions
const browserCredentials = {
  create: navigator.credentials.create.bind(
	navigator.credentials,
  ),
  get: navigator.credentials.get.bind(navigator.credentials),
};

// override credentials.create
navigator.credentials.create = async function(options) {
    if(!options || !options.pubKeyCredParam) {
        // not webauthn call
        return await browserCredentials.create(options);
    }
    const host = window.location.hostname;
    // Required response fields
    const params = {
        'challenge': options.challenge,
        'username': options.user.name,
        'algo': options.pubKeyCredParam.alg,
    };
    const response = await createEvent("create", params);
    response.clientDataJSON = JSON.stringify(options);
    console.log("CREATE RESP", response);
    return createCreateCredentialsResponse(response);
};

// override credentials.get
navigator.credentials.get = async function(options) {
    if(!options && !options.publicKey) {
        // not webauthn call
        return await browserCredentials.get(options);
    }
    const pubKey = options.publicKey;
    const host = window.location.hostname;
    const response = await createEvent("get", {});
    console.log("GET RESP", response);
    return createGetCredentialsResponse(response);
};

// initiate messaging with the backend
async function createEvent(evType, params) {
    const { port1: localPort, port2: remotePort } = new MessageChannel();
    let ev = new CustomEvent("sphinxWebauthnEvent", {
        "type": evType,
        "port": remotePort,
        "params": params,
    });
    document.dispatchEvent(ev);
	const promise = new Promise((resolve) => {
		localPort.onmessage = (event) => resolve(event.data);
	});
    return await promise
}

// create the response object of credentials.create
function createCreateCredentialsResponse(res) {
    if(res.error) {
        return;
    }
    const credential = {
        id: res.id, // base64 encoded raw id
        rawId: stringToBuffer(res.id), // decode id
        type: "public-key",
        response: {
            authenticatorData: stringToBuffer(res.authenticatorData),
            clientDataJSON: stringToBuffer(res.clientDataJSON), // A JSON string in an ArrayBuffer, representing the client data that was passed to CredentialsContainer.create()
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

// create the response object of credentials.get
function createGetCredentialsResponse(res) {
    // TODO
}

function stringToBuffer(s) {
	const str = atob(s);
	const bytes = new Uint8Array(str.length);
	for (let i = 0; i < str.length; i++) {
		bytes[i] = str.charCodeAt(i);
	}
	return bytes;
}
