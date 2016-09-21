var register = document.getElementById("js-ServiceWorker-Register");
var push     = document.getElementById("js-PushPermission");

register.addEventListener("click", function() {
    navigator.serviceWorker.register("./ServiceWorker.js", {scope: "./"})
    .then(function() {
        if ( Notification.permission === "granted" ) {
            console.log("Notification has already granted");
            push.disabled = true;
        } else {
            Notification.requestPermission(function(perm) {
                if ( perm === "granted" ) {
                    push.disabled = true;
                }
            });
        }
    });
});

var subscription = null;
navigator.serviceWorker.ready.then(function(sw) {
    sw.pushManager.getSubscription().then(sOK, sNG);
});

function sOK(ss) {
    if ( ! ss ) {
        console.log("=====NG====");
        return sNG();
    }

    console.log(ss);
    console.log("auth", abToBase64(ss.getKey("auth")));
    console.log("key", abToBase64(ss.getKey("p256dh")));
    console.log("endpoint", ss.endpoint);

    register.disabled = true;
    subscription = ss;
    registerNotification(ss);
}

function abToBase64(ab) {
    var bin = "";
    var bytes = new Uint8Array(ab);
    var size = bytes.length;
    for ( var i = 0; i < size; i++ ) {
        bin += String.fromCharCode(bytes[i]);
    }

    console.log(window.btoa(bin))
    return base64URLEncode(bin);
}

function sNG(err) {
    console.log("subscription failed", err);
    register.disabled = true;
    subscription = null;
}


push.addEventListener("click", function() {
    if ( subscription ) {
        navigator.serviceWorker.ready.then(unsubscribe);
        return;
    }

    if ( Notification.permission === "denied" ) {
        return alert("Disabled push");
    }

    navigator.serviceWorker.ready.then(subscribe);
});

function base64URLEncode(buf) {
    return window.btoa(buf)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/g, "");
}

function base64URLDecode(str) {
    str += Array(5 - str.length % 4).join("=");
    str = str.replace(/\-/g, "+")
            .replace(/\_/g, "/");

    return window.atob(str);
}

function subscribe(sw) {
    var key = base64URLDecode("BPC-FCjm9OhqYqFCGzXCxm2KPStFcLDIz35jMCx5hbX6rlJZmAPALG1YcHDgKPMDZe2sGwxzMvh-VIcAeSZ6L2U");
    var size = key.length;
    var pubKey = new Uint8Array(size);
    for ( var i = 0; i < size; i++ ) {
        pubKey[i] = key.charCodeAt(i);
    }
    sw.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: pubKey
    })
    .then(sOK, sNG);
}

function unsubscribe() {
    if ( subscription ) {
        subscription.unsubscribe();
    }
    sNG();
}

function registerNotification(s) {
    var endpoint = s.endpoint;
    if ( ("subscriptionId" in s) && s.endpoint.indexOf(s.subscriptionId) === -1 ) {
        endpoint += "/" + s.subscriptionId;
    }
}
