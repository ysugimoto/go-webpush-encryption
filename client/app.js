var register = document.getElementById("js-ServiceWorker-Register");
var push     = document.getElementById("js-PushPermission");

register.addEventListener("click", function() {
    navigator.serviceWorker.register("./ServiceWorker.js", {scope: "./"})
    .then(function() {
        if ( Notification.permission === "granted" ) {
            console.log("Notification has already granted");
            push.disabled = true;
        } else {
            Notification.checkPermission(function(perm) {
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
        return sNG();
    }

    console.log(ss);

    register.disabled = true;
    subscription = ss;
    registerNotification(ss);
}

function sNG() {
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

function subscribe(sw) {
    sw.pushManager.subscribe({
        userVisibleOnly: true
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
