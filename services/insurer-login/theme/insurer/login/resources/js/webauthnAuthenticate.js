// Keycloak 26.8.1 の theme/base/login/resources/js/webauthnAuthenticate.js（Apache License 2.0）を写し、
// passkey でのログインを待つ間の表示と、ページの操作の停止（authenticateByWebAuthn の入口と showWaiting）だけを足した。版を上げるときは、元のファイルと比べ直す。
// 端末の確認画面（Windows Hello など）が出るまで数秒かかることがあり、その間に何も出ないと、利用者は押し損ないを疑う。
import { base64url } from "rfc4648";

// singleton
let abortController = undefined;

export function signal() {
    if (abortController) {
        // abort the previous call
        const abortError = new Error("Cancelling pending WebAuthn call");
        abortError.name = "AbortError";
        abortController.abort(abortError);
    }

    abortController = new AbortController();
    return abortController.signal;
}

export async function authenticateByWebAuthn(input) {
    showWaiting();
    const allowCredentials = input.isUserIdentified ? getAllowCredentials() : [];
    try {
        const result = await doAuthenticate({ ...input, allowCredentials });
        if (result) returnSuccess(result);
    } catch (error) {
        returnFailure(error);
    }
}

/**
 * Reads the allowed credentials from the hidden authn_select form.
 * Exported so that passkeysConditionalAuth.js can use them as well.
 */
export function getAllowCredentials() {
    const allowCredentials = [];
    const authnUse = document.forms['authn_select']?.authn_use_chk;
    if (authnUse !== undefined) {
        if (authnUse.length === undefined) {
            allowCredentials.push({
                id: base64url.parse(authnUse.value, { loose: true }),
                type: 'public-key',
            });
        } else {
            authnUse.forEach((entry) =>
                allowCredentials.push({
                    id: base64url.parse(entry.value, { loose: true }),
                    type: 'public-key',
                }));
        }
    }
    return allowCredentials;
}

/**
 * Core function for navigator.credentials.get().
 * Exported so that passkeysConditionalAuth.js does not need its own copy.
 *
 * input: { challenge, userVerification, rpId, createTimeout, errmsg,
 *           allowCredentials?: PublicKeyCredentialDescriptor[],
 *           additionalOptions?: object  ← e.g. { mediation: "conditional" | "optional" | "required" | "silent" } }
 */
export function doAuthenticate(input) {
    // Check if WebAuthn is supported by this browser
    if (!window.PublicKeyCredential) {
        returnFailure("WebAuthnUnsupportedBrowser");
        return;
    }

    const publicKey = {
        rpId: input.rpId,
        challenge: base64url.parse(input.challenge, { loose: true }),
    };

    if (input.createTimeout !== 0) {
        publicKey.timeout = input.createTimeout * 1000;
    }

    if (input.allowCredentials !== undefined) {
        publicKey.allowCredentials = input.allowCredentials;
    }

    if (input.userVerification !== 'not specified') {
        publicKey.userVerification = input.userVerification;
    }

    return navigator.credentials.get({
        publicKey: publicKey,
        signal: signal(),
        ...input.additionalOptions,
    });
}

export function returnSuccess(result) {
    document.getElementById("clientDataJSON").value = base64url.stringify(new Uint8Array(result.response.clientDataJSON), { pad: false });
    document.getElementById("authenticatorData").value = base64url.stringify(new Uint8Array(result.response.authenticatorData), { pad: false });
    document.getElementById("signature").value = base64url.stringify(new Uint8Array(result.response.signature), { pad: false });
    document.getElementById("credentialId").value = result.id;
    if (result.response.userHandle) {
        document.getElementById("userHandle").value = base64url.stringify(new Uint8Array(result.response.userHandle), { pad: false });
    }
    const rememberMe = document.getElementById("rememberMe");
    if (rememberMe) {
        const rememberMeInput = document.createElement("input");
        rememberMeInput.type = "hidden";
        rememberMeInput.name = "rememberMe";
        rememberMeInput.value = rememberMe.checked ? "on" : "off";
        document.getElementById("webauth").appendChild(rememberMeInput);
    }
    document.getElementById("webauth").requestSubmit();
}

export function returnFailure(err) {
    document.getElementById("error").value = err;
    document.getElementById("webauth").requestSubmit();
}

/**
 * 端末の確認画面を待っていることを示し、ページの操作を止める。待っている間にパスワードのフォームを送ったりリンクを開いたりすると、
 * ページが替わって passkey の要求が切れる。成功でも失敗でもフォームを送ってページが替わるので、元に戻さない。
 * passkey の結果を送る隠しフォーム（webauth、authn_select）は、止めると値が送られないので、触らない。
 */
function showWaiting() {
    const button = document.getElementById("authenticateWebAuthnButton");
    if (!button || document.getElementById("webauthn-waiting")) return;
    const hidden = (el) => el.closest("#webauth, #authn_select");
    for (const el of document.querySelectorAll("button, input, select, textarea")) {
        if (!hidden(el) && el.type !== "hidden") el.disabled = true;
    }
    // ボタンは、ログインの画面では a 要素である。リンクは disabled を持たないので、押せなくする
    for (const el of document.querySelectorAll("a")) {
        el.setAttribute("aria-disabled", "true");
        el.style.pointerEvents = "none";
        el.tabIndex = -1;
    }
    button.setAttribute("aria-busy", "true");
    button.style.opacity = "0.6";
    const status = document.createElement("p");
    status.id = "webauthn-waiting";
    status.setAttribute("role", "status");
    status.textContent = "端末の確認画面（PIN、指紋、顔）を待っています。表示まで数秒かかることがあります。";
    status.style.marginTop = "0.5rem";
    button.insertAdjacentElement("afterend", status);
}
