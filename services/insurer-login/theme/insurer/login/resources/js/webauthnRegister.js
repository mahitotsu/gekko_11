// Keycloak 26.8.1 の theme/base/login/resources/js/webauthnRegister.js（Apache License 2.0）を写し、
// 登録した passkey の名前の付け方（returnSuccess の中と environmentName）だけを替えた（D-42、D-43）。版を上げるときは、元のファイルと比べ直す。
import { base64url } from "rfc4648";

export async function registerByWebAuthn(input) {

    // Check if WebAuthn is supported by this browser
    if (!window.PublicKeyCredential) {
        returnFailure("WebAuthnUnsupportedBrowser");
        return;
    }

    const publicKey = {
        challenge: base64url.parse(input.challenge, {loose: true}),
        rp: {id: input.rpId, name: input.rpEntityName},
        user: {
            id: base64url.parse(input.userid, {loose: true}),
            name: input.username,
            displayName: input.username
        },
        pubKeyCredParams: getPubKeyCredParams(input.signatureAlgorithms),
    };

    if (input.attestationConveyancePreference !== 'not specified') {
        publicKey.attestation = input.attestationConveyancePreference;
    }

    const authenticatorSelection = {};
    let isAuthenticatorSelectionSpecified = false;

    if (input.authenticatorAttachment !== 'not specified') {
        authenticatorSelection.authenticatorAttachment = input.authenticatorAttachment;
        isAuthenticatorSelectionSpecified = true;
    }

    if (input.residentKey && input.residentKey !== 'not specified') {
        // residentKey is the current spec field and the source of truth. requireResidentKey is
        // deprecated but still set for older clients: it is true iff residentKey is 'required'.
        authenticatorSelection.residentKey = input.residentKey;
        authenticatorSelection.requireResidentKey = input.residentKey === 'required';
        isAuthenticatorSelectionSpecified = true;
    } else if (input.requireResidentKey !== 'not specified') {
        // fall back to the deprecated option when residentKey is not specified
        if (input.requireResidentKey === 'Yes') {
            authenticatorSelection.residentKey = 'required';
            authenticatorSelection.requireResidentKey = true;
        } else {
            authenticatorSelection.residentKey = 'discouraged';
            authenticatorSelection.requireResidentKey = false;
        }
        isAuthenticatorSelectionSpecified = true;
    }

    if (input.userVerificationRequirement !== 'not specified') {
        authenticatorSelection.userVerification = input.userVerificationRequirement;
        isAuthenticatorSelectionSpecified = true;
    }

    if (isAuthenticatorSelectionSpecified) {
        publicKey.authenticatorSelection = authenticatorSelection;
    }

    if (input.createTimeout !== 0) {
        publicKey.timeout = input.createTimeout * 1000;
    }

    const excludeCredentials = getExcludeCredentials(input.excludeCredentialIds);
    if (excludeCredentials.length > 0) {
        publicKey.excludeCredentials = excludeCredentials;
    }

    try {
        const result = await doRegister(publicKey);
        returnSuccess(result, input.initLabel, input.initLabelPrompt);
    } catch (error) {
        returnFailure(error);
    }
}

function doRegister(publicKey) {
    return navigator.credentials.create({publicKey});
}

function getPubKeyCredParams(signatureAlgorithmsList) {
    const pubKeyCredParams = [];
    if (signatureAlgorithmsList.length === 0) {
        pubKeyCredParams.push({type: "public-key", alg: -7});
        return pubKeyCredParams;
    }

    for (const entry of signatureAlgorithmsList) {
        pubKeyCredParams.push({
            type: "public-key",
            alg: entry
        });
    }

    return pubKeyCredParams;
}

function getExcludeCredentials(excludeCredentialIds) {
    const excludeCredentials = [];
    if (excludeCredentialIds === "") {
        return excludeCredentials;
    }

    for (const entry of excludeCredentialIds.split(',')) {
        excludeCredentials.push({
            type: "public-key",
            id: base64url.parse(entry, {loose: true})
        });
    }

    return excludeCredentials;
}

function getTransportsAsString(transportsList) {
    if (!Array.isArray(transportsList)) {
        return "";
    }

    return transportsList.join();
}

function returnSuccess(result, initLabel, initLabelPrompt) {
    document.getElementById("clientDataJSON").value = base64url.stringify(new Uint8Array(result.response.clientDataJSON), {pad: false});
    document.getElementById("attestationObject").value = base64url.stringify(new Uint8Array(result.response.attestationObject), {pad: false});
    document.getElementById("publicKeyCredentialId").value = base64url.stringify(new Uint8Array(result.rawId), {pad: false});

    if (typeof result.response.getTransports === "function") {
        const transports = result.response.getTransports();
        if (transports) {
            document.getElementById("transports").value = getTransportsAsString(transports);
        }
    } else {
        console.log("Your browser is not able to recognize supported transport media for the authenticator.");
    }

    if (result.authenticatorAttachment) {
        document.getElementById("authenticatorAttachment").value = result.authenticatorAttachment;
    }

    // 名前を prompt() で尋ねない。prompt() を使えないブラウザ（VS Code に内蔵されたブラウザなど）では、登録が失敗するため。
    // 一覧で、使えなくなった端末の passkey を見分けられるよう、作った環境と日時を名前にする。日時を入れると、同じ名前の拒否も避けられる（F-G92、D-43）
    const environment = environmentName();
    document.getElementById("authenticatorLabel").value = `${environment ? `${environment}で作成` : initLabel}（${new Date().toLocaleString("ja-JP")}）`;

    document.getElementById("register").requestSubmit();
}

/** 作った環境の名前（例: Windows・Chrome）。ブラウザの情報から作る。分からなければ空。 */
function environmentName() {
    const ua = navigator.userAgent;
    const os = /Windows/.test(ua) ? "Windows" : /iPhone|iPad/.test(ua) ? "iPhone・iPad" : /Android/.test(ua) ? "Android"
        : /Mac OS X/.test(ua) ? "Mac" : /CrOS/.test(ua) ? "ChromeOS" : /Linux/.test(ua) ? "Linux" : "";
    const browser = /Edg\//.test(ua) ? "Edge" : /Code\//.test(ua) ? "VS Code" : /Firefox\//.test(ua) ? "Firefox"
        : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "";
    return [os, browser].filter(Boolean).join("・");
}

function returnFailure(err) {
    document.getElementById("error").value = err;
    document.getElementById("register").requestSubmit();
}
