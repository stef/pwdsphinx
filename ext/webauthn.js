// save original credential functions
const browserCredentials = {
  create: navigator.credentials.create.bind(navigator.credentials),
  get: navigator.credentials.get.bind(navigator.credentials),
};


// override credentials.create
navigator.credentials.create = async function(args) {
    let options = args.publicKey;
    if(!options || !options.pubKeyCredParams) {
        // not webauthn call
        // TODO throw popop warning
        return await browserCredentials.create(options);
    }
    let hasSupportedAlgo = false;
    for(let a of options.pubKeyCredParams) {
        if(a.alg == -8) {
            hasSupportedAlgo = true;
            break;
        }
    }
    if(!hasSupportedAlgo) {
        return await browserCredentials.create(options);
    }
    const host = window.location.hostname;
    // Required response fields
    const params = {
        'challenge': arrayBufferToBase64(options.challenge),
        'username': options.user.name,
        'userid': arrayBufferToBase64(options.user.id),
        //algos:
        // -8: Ed25519 !!
		// -7: ES256
		// -257: RS256
        'algos': options.pubKeyCredParams,
    };
    console.log("SENDING PARAMS TO CS", params);
    let response = await createEvent("webauthn-create", params);
    response.clientDataJSON = JSON.stringify(options);
    console.log("CREATE RESP", response);
    let createObj = createCreateCredentialsResponse(response);
    return createObj;
};

// override credentials.get
navigator.credentials.get = async function(options) {
    if(!options && !options.publicKey) {
        // not webauthn call
        return await browserCredentials.get(options);
    }
    console.log("GET webauth", options);
    const pubKey = options.publicKey;
    const response = await createEvent("webauthn-get", {});
    response.clientDataJSON = JSON.stringify(options);
    console.log("GET RESP", response);
    return createGetCredentialsResponse(response);
};

// initiate messaging with the backend
async function createEvent(action, params) {
    let msg = {
        "type": "sphinxWebauthnEvent",
        "action": action,
        "params": params,
    };
    const { port1: localPort, port2: remotePort } = new MessageChannel();
	const promise = new Promise((resolve) => {
		localPort.onmessage = (event) => {
            resolve(event.data);
        }
	});
    try {
        window.postMessage(msg, '*', [remotePort]);
    } catch(err) {
        console.log("Failed to send message to content script:", err);
    }
    let resp = await promise;
    return resp;
}

// create the response object of credentials.create
function createCreateCredentialsResponse(res) {
    if(res.error) {
        return;
    }
    const credential = {
        id: res.id, // base64 encoded raw id
        rawId: stringToBuffer(res.id, true), // decode id
        type: "public-key",
        response: {
            authenticatorData: stringToBuffer(res.authenticatorData),
            clientDataJSON: stringToBuffer(res.clientDataJSON), // A JSON string in an ArrayBuffer, representing the client data that was passed to CredentialsContainer.create()
            signature: stringToBuffer(res.signature),
            userHandle: stringToBuffer(res.userHandle),
        },
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

function stringToBuffer(s, isB64) {
    if(!s) {
        return new Uint8Array(0);
    }
    if(isB64) {
        s = atob(s.replaceAll('-', '+').replaceAll('_', '/'));
    }
    const arr = Uint8Array.from(str, c => c.charCodeAt(0));
    return arr.buffer;
}

function arrayBufferToBase64(buffer) {
	let binary = '';
	const bytes = new Uint8Array( buffer );
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return window.btoa(binary);
}
