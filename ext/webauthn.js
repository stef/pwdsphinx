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
    //algos:
    // -8: Ed25519 <- only supported
    // -7: ES256
    // -257: RS256
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
    options.challenge = arrayBufferToBase64(options.challenge);
    options["type"] = "webauthn.create";
    options["origin"] = window.location.origin;
    // Required response fields
    const params = {
        'challenge': options.challenge,
        'username': options.user.name,
        'userid': arrayBufferToBase64(options.user.id),
        'clientDataJSON': JSON.stringify(options),
    };
    let response = await createEvent("webauthn-create", params);
    response.clientDataJSON = JSON.stringify(options);
    let createObj = createCreateCredentialsResponse(response);
    return createObj;
};

// override credentials.get
navigator.credentials.get = async function(options) {
    if(!options && !options.publicKey) {
        // not webauthn call
        return await browserCredentials.get(options);
    }
    const pubKeyObj = options.publicKey;
    if(pubKeyObj['allowCredentials'].length == 0) {
        return await browserCredentials.get(options);
    }
    const key = pubKeyObj['allowCredentials'][0].id;
    options["type"] = "webauthn.get";
    options["origin"] = window.location.origin;
    options["challenge"] = arrayBufferToBase64(pubKeyObj.challenge);
    // Required response fields
    const params = {
        'pk': arrayBufferToBase64(key),
        'challenge': arrayBufferToBase64(pubKeyObj.challenge),
        'clientDataJSON': JSON.stringify(options),
    };
    const response = await createEvent("webauthn-get", params);
    response.challenge = pubKeyObj.challenge;
    response.clientDataJSON = JSON.stringify(options);
    let getObj = createGetCredentialsResponse(response);
    return getObj;
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
    res.pk = res.pk.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const credential = {
        id: res.pk,
        rawId: stringToBuffer(res.pk, true),
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
            // TODO attestationObject https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject
            attestationObject: stringToBuffer(res.attestationObject, true),
            clientDataJSON: stringToBuffer(res.clientDataJSON), // A JSON string in an ArrayBuffer, representing the client data that was passed to CredentialsContainer.create()
            publicKeyAlgorithm: -8,
            transports: ["internal"],
            //getPublicKey: () => stringToBuffer(res.pk, true),
            //getPublicKeyAlgorithm: () => -8,
            //getTransport: () => "",
            //getAuthenticatorData: () => "",
        },
        key: stringToBuffer(res.pk, true),
        getClientExtensionResults: () => {},
    };
    Object.setPrototypeOf(credential.response, AuthenticatorAttestationResponse.prototype);
    Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
    credential.response.getTransports = () => credential.response.transports;
    credential.response.getPublicKey = () => credential.rawId;
    credential.response.getPublicKeyAlgorithm = () => -8;
    credential.response.getAuthenticatorData = () => stringToBuffer(res.authData, true);
    return credential;
}

// create the response object of credentials.get
function createGetCredentialsResponse(res) {
    if(res.error) {
        return;
    }
    res.pk = res.pk.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const credential = {
        id: res.pk,
        rawId: stringToBuffer(res.pk, true),
        challenge: res.challenge,
        response: {
            clientDataJSON: stringToBuffer(res.clientDataJSON), // A JSON string in an ArrayBuffer, representing the client data that was passed to CredentialsContainer.create()
            authenticatorData: stringToBuffer(res.authData, true),
            signature: stringToBuffer(res.sig, true),
            userHandle: res.userid,
        },
        type: "public-key",
        authenticatorAttachment: null,
    }
    credential.getClientExtensionResults = () => {};
    return credential;
}

function stringToBuffer(s, isB64) {
    if(!s) {
        return new Uint8Array(0);
    }
    if(isB64) {
        s = atob(s.replaceAll('-', '+').replaceAll('_', '/'));
    }
    const arr = Uint8Array.from(s, c => c.charCodeAt(0));
    return arr.buffer;
}

function arrayBufferToBase64(buffer) {
	let binary = '';
	const bytes = new Uint8Array( buffer );
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return toBase64(binary);
}

function toBase64(s) {
	return window.btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
