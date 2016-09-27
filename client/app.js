function WebPushSample(register, subscribe, unsubscribe, payload, send, log, params) {
    this.register_    = register;
    this.subscribe_   = subscribe;
    this.unsubscribe_ = unsubscribe;
    this.payload_     = payload;
    this.send_        = send;
    this.log_         = log;
    this.params_      = params;

    this.subscription_ = null;

    this.init();
}

// constants
WebPushSample.PERMISSION_GRANTED = "granted";
WebPushSample.PERMISSION_DENIED  = "denied";
WebPushSample.STATUS_OK  = "ok";
WebPushSample.STATUS_NG  = "ng";

WebPushSample.prototype.init = function WebPushSample_prepare() {
    this.register_.addEventListener("click", this);
    this.subscribe_.addEventListener("click", this);
    this.unsubscribe_.addEventListener("click", this);
    this.send_.addEventListener("click", this);

    navigator.serviceWorker.ready.then(function(sw) {
        this.register_.disabled = true;
        this.register_.classList.add("is-disabled");
        this.setStatus(0, WebPushSample.STATUS_OK);
        sw.pushManager.getSubscription()
        .then(
            this.subscriptionSuccess.bind(this),
            this.subscriptionError.bind(this)
        );
    }.bind(this));
};

WebPushSample.prototype.log = function WebPushSample_log(message) {
    var line = document.createElement("p");
    line.appendChild(document.createTextNode(message));

    this.log_.appendChild(line);
};

WebPushSample.prototype.subscribe = function WebPushSample_subscribe(sw) {
    var key     = this.decodeURLBase64("BPC-FCjm9OhqYqFCGzXCxm2KPStFcLDIz35jMCx5hbX6rlJZmAPALG1YcHDgKPMDZe2sGwxzMvh-VIcAeSZ6L2U");
    var size    = key.length;
    var options = {
        userVisibleOnly: true,
        applicationServerKey: new Uint8Array(size)
    };

    for ( var i = 0; i < size; i++ ) {
        options.applicationServerKey[i] = key.charCodeAt(i);
    }

    sw.pushManager.subscribe(options)
    .then(this.subscriptionSuccess.bind(this), this.subscriptionError.bind(this));
};

WebPushSample.prototype.unsubscribe = function WebPushSample_unsubscribe() {
    if ( ! this.subscription_ ) {
        return;
    }

    this.subscription_.unsubscribe();
    this.params_[0].textContent = "";
    this.params_[1].textContent = "";
    this.params_[2].textContent = "";
    this.payload_.disabled = true;
    this.payload_.classList.add("is-disabled");
    this.send_.disabled = true;
    this.send_.classList.add("is-disabled");
    this.togglePushButton(false);
    this.setStatus(2, WebPushSample.STATUS_NG);
    this.log("unsubscribe");
};

WebPushSample.prototype.subscriptionSuccess = function WebPushSample_subscriptionSuccess(subscription) {
    if ( ! subscription ) {
        this.togglePushButton(false);
        return;
    }

    this.log("subscribe success");
    this.log(JSON.stringify(subscription));

    this.subscription_ = subscription;
    this.params_[0].textContent = subscription.endpoint;
    this.params_[1].textContent = this.encodeURLBase64(subscription.getKey("p256dh"));
    this.params_[2].textContent = this.encodeURLBase64(subscription.getKey("auth"));

    this.payload_.disabled = false;
    this.payload_.classList.remove("is-disabled");
    this.send_.disabled = false;
    this.send_.classList.remove("is-disabled");

    this.togglePushButton(true);
    this.setStatus(2, WebPushSample.STATUS_OK);

};

WebPushSample.prototype.encodeURLBase64 = function WebPushSample_encodeURLBase64(buffer) {
    var bin  = "";
    var view = new Uint8Array(buffer);
    var size = view.length;

    for ( var i = 0; i < size; i++ ) {
        bin += String.fromCharCode(view[i]);
    }

    return window.btoa(bin)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/g, "");
};

WebPushSample.prototype.decodeURLBase64 = function WebPushSample_decodeURLBase64(str) {
    str += Array(5 - str.length % 4).join("=");
    str = str.replace(/\-/g, "+").replace(/\_/g, "/");

    return window.atob(str);
}

WebPushSample.prototype.subscriptionError = function WebPushSample_subscriptionError(err) {
    this.log("subscription failed", err);
    this.subscription_ = null;

    this.payload_.disabled = true;
    this.payload_.classListt.add("is-disabled");
    this.send_.disabled = true;
    this.send_.classListt.add("is-disabled");
};

WebPushSample.prototype.togglePushButton = function WebPushSample_togglePushButton(active) {
    if ( active ) {
        this.subscribe_.disabled = true;
        this.subscribe_.classList.add("is-disabled");
        this.unsubscribe_.disabled = false;
        this.unsubscribe_.classList.remove("is-disabled");
        this.setStatus(1, WebPushSample.STATUS_OK);
    } else {
        this.subscribe_.disabled = false;
        this.subscribe_.classList.remove("is-disabled");
        this.unsubscribe_.disabled = true;
        this.unsubscribe_.classList.add("is-disabled");
        this.setStatus(1, WebPushSample.STATUS_NG);
    }
};

WebPushSample.prototype.setStatus = function WebPushSample_setStatus(index, state) {
    var elements = document.querySelectorAll(".status span");
    if ( ! elements[index] ) {
        return;
    }

    var element = elements[index];
    element.className = "";

    switch ( state ) {
        case WebPushSample.STATUS_OK:
            element.classList.add("ok");
            element.textContent = "Ready";
            break;

        case WebPushSample.STATUS_NG:
            element.classList.add("ng");
            element.textContent = "Not Ready";
            break;
    }
}

WebPushSample.prototype.sendPush = function WebPushSample_sendPush(payload) {
    // TODO: implement
};

WebPushSample.prototype.handleEvent = function WebPushSample_handleEvent(evt) {
    if ( evt.type !== "click" ) {
        return;
    }

    switch ( evt.target ) {
        case this.register_:
            this.log("Boot serviceworker...");
            navigator.serviceWorker.register("./ServiceWorker.js", {scope: "./"})
            .then(function() {
                this.setStatus(0, WebPushSample.STATUS_OK);
                if ( Notification.permission === WebPushSample.PERMISSION_GRANTED ) {
                    this.log("Notification has already granted");
                    this.togglePushButton(true);
                } else {
                    this.log("Notification permission request");
                    Notification.requestPermission(function(permission) {
                        if ( permission !== WebPushSample.PERMISSION_GRANTED ) {
                            return;
                        }
                        this.log("Notification granted");
                        this.togglePushButton(true);
                    }.bind(this));
                }
            }.bind(this));
            break;

        case this.subscribe_:
            if ( Notification.permission === WebPushSample.PERMISSION_DENIED ) {
                this.log("Disabled push");
                this.togglePushButton(false);
                return;
            }

            navigator.serviceWorker.ready.then(this.subscribe.bind(this));
            break;

        case this.unsubscribe_:
            if ( ! this.subscription_ ) {
                return;
            }

            navigator.serviceWorker.ready.then(this.unsubscribe.bind(this));
            break;

        case this.send_:
            var payload = this.payload_.value;

            this.sendPush(payload);
            break;
    }
};

var wp = new WebPushSample(
    document.getElementById("js-ServiceWorker-Register"),
    document.getElementById("js-PushSubscribe"),
    document.getElementById("js-PushUnsubscribe"),
    document.getElementById("js-PushMessage"),
    document.getElementById("js-SendPush"),
    document.getElementById("js-Logs"),
    document.querySelectorAll(".subscriptions span")
);
