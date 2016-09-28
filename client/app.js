/**
 * Application button / text element wrapper
 *
 * @constructor
 */
function AppElement(element) {
    this.element_ = element;
}
(function() {
// Header
AppElement.prototype = {
    enable:  AppElement_enable,
    disable: AppElement_disable,
    click:   AppElement_click,
    value:   AppElement_value,
    text:    AppElement_text,
    element: AppElement_element
};
// Implements
function AppElement_enable() {
    this.element_.disabled = false;
    this.element_.classList.remove("is-disabled");
}
function AppElement_disable() {
    this.element_.disabled = true;
    this.element_.classList.add("is-disabled");
}
function AppElement_click(observer) {
    this.element_.addEventListener("click", observer);
}
function AppElement_value() {
    return ( this.element_.tagName === "INPUT" ) ? this.element_.value : "";
}
function AppElement_text(text) {
    this.element_.textContent = text;
}
function AppElement_element() {
    return this.element_;
}
})();

/**
 * encode / decode utility
 */
var Util = (function() {
// Header
return {
    encodeURLBase64: Util_encodeURLBase64,
    decodeURLBase64: Util_decodeURLBase64,
    fixHeight:       Util_fixHeight
};
// Implements
function Util_encodeURLBase64(buffer) {
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
}
function Util_decodeURLBase64(str) {
    str += Array(5 - str.length % 4).join("=");
    str = str.replace(/\-/g, "+").replace(/\_/g, "/");

    return window.atob(str);
}
function Util_fixHeight(element) {
    var r = element.getBoundingClientRect();

    element.style.height = (window.innerHeight - r.top - 40) + "px";
}
})();

/**
 * WebPush application constructor
 *
 * @constructor
 */
function WebPushSample(params) {
    this.register_      = new AppElement(params.register);
    this.subscribe_     = new AppElement(params.subscribe);
    this.unsubscribe_   = new AppElement(params.unsubscribe);
    this.send_          = new AppElement(params.send);
    this.payload_       = new AppElement(params.payload);

    this.log_           = params.log;
    this.states_        = params.states;
    this.subscriptions_ = {
        endpoint: new AppElement(params.subscriptions[0]),
        key:      new AppElement(params.subscriptions[1]),
        auth:     new AppElement(params.subscriptions[2])
    };

    this.server_        = params.server;
    this.subscription_  = null;
}

// constants
WebPushSample.PERMISSION_GRANTED  = "granted";
WebPushSample.PERMISSION_DENIED   = "denied";
WebPushSample.STATUS_OK           = "ok";
WebPushSample.STATUS_NG           = "ng";
WebPushSample.STATE_SERVICEWORKER = 0;
WebPushSample.STATE_SERVERKEY     = 1;
WebPushSample.STATE_PERMISSION    = 2;
WebPushSample.STATE_SUBSCRIPTION  = 3;
WebPushSample.LOGLEVEL_DEFAULT    = 4;
WebPushSample.LOGLEVEL_SUCCESS    = 5;
WebPushSample.LOGLEVEL_ERROR      = 6;

(function() {
// Header
WebPushSample.init      = WebPushSample_init;
WebPushSample.prototype = {
    prepare:                     WebPushSample_prepare,
    log:                         WebPushSample_log,
    subscribe:                   WebPushSample_subscribe,
    unsubscribe:                 WebPushSample_unsubscribe,
    subscriptionSuccess:         WebPushSample_subscriptionSuccess,
    subscriptionError:           WebPushSample_subscriptionError,
    togglePushButton:            WebPushSample_togglePushButton,
    setStatus:                   WebPushSample_setStatus,
    sendPush:                    WebPushSample_sendPush,
    handleRegisterServiceWorker: WebPushSample_handleRegisterServiceWorker,
    handleEvent:                 WebPushSample_handleEvent
};

// Implements
function WebPushSample_init(params) {
    var instance = new WebPushSample(params);

    instance.prepare();
}

function WebPushSample_prepare() {
    // register click events
    this.register_.click(this);
    this.subscribe_.click(this);
    this.unsubscribe_.click(this);
    this.send_.click(this);

    // boot handler
    navigator.serviceWorker.ready.then(function(sw) {
        this.log("ServiceWorker ready", WebPushSample.LOGLEVEL_SUCCESS);
        this.register_.disable();
        this.setStatus(WebPushSample.STATE_SERVICEWORKER, WebPushSample.STATUS_OK);
        sw.pushManager.getSubscription()
        .then(
            this.subscriptionSuccess.bind(this),
            this.subscriptionError.bind(this)
        );
    }.bind(this));

    // Log element height fix
    var timer = null;
    window.addEventListener("resize", function() {
        if ( timer ) {
            return;
        }
        timer = setTimeout(function() {
            Util.fixHeight(this.log_);
            timer = null;
        }.bind(this), 10);
    }.bind(this));
    Util.fixHeight(this.log_);
}

function WebPushSample_log(message, level) {
    var line = document.createElement("p");
    line.appendChild(document.createTextNode(message));

    switch ( level || WebPushSample.LOGLEVEL_DEFAULT ) {
        case WebPushSample.LOGLEVEL_SUCCESS:
            line.classList.add("success");
            break;
        case WebPushSample.LOGLEVEL_ERROR:
            line.classList.add("error");
            break;
        default:
            break;
    }
    this.log_.appendChild(line);

}

function WebPushSample_subscribe(sw) {
    fetch(this.server_ + "/key")
    .then(function(response) {
        if ( ! response.ok ) {
            return this.log("[ERROR] Server respond error: " + response.status + " / " + response.statusText, WebPushSample.LOGLEVEL_ERROR);
        }

        response.text().then(function(pubkey) {
            this.setStatus(WebPushSample.STATE_SERVERKEY, WebPushSample.STATUS_OK);

            var key     = Util.decodeURLBase64(pubkey);
            var size    = key.length;
            var options = {
                userVisibleOnly: true,
                applicationServerKey: new Uint8Array(size)
            };

            for ( var i = 0; i < size; i++ ) {
                options.applicationServerKey[i] = key.charCodeAt(i);
            }

            sw.pushManager.subscribe(options)
            .then(
                this.subscriptionSuccess.bind(this),
                this.subscriptionError.bind(this)
            );
        }.bind(this));
    }.bind(this))
    .catch(function(err) {
        this.log("[ERROR] " + err);
    }.bind(this));
}

function WebPushSample_unsubscribe() {
    if ( ! this.subscription_ ) {
        return;
    }

    this.subscription_.unsubscribe();
    this.subscriptions_.endpoint.text("");
    this.subscriptions_.key.text("");
    this.subscriptions_.auth.text("");

    this.payload_.disable();
    this.send_.disable();
    this.togglePushButton(false);
    this.setStatus(WebPushSample.STATE_SUBSCRIPTION, WebPushSample.STATUS_NG);
    this.log("unsubscribe");
}

function WebPushSample_subscriptionSuccess(subscription) {
    if ( ! subscription ) {
        this.togglePushButton(false);
        return;
    }

    this.log("subscribe success", WebPushSample.LOGLEVEL_SUCCESS);
    this.log(JSON.stringify(subscription));

    this.subscription_ = subscription;
    this.subscriptions_.endpoint.text(subscription.endpoint);
    this.subscriptions_.key.text(Util.encodeURLBase64(subscription.getKey("p256dh")));
    this.subscriptions_.auth.text(Util.encodeURLBase64(subscription.getKey("auth")));

    this.payload_.enable();
    this.send_enable();
    this.togglePushButton(true);
    this.setStatus(3, WebPushSample.STATUS_OK);
}

function WebPushSample_subscriptionError(err) {
    this.log("subscription failed", err);
    this.subscription_ = null;

    this.payload_.disable();
    this.send_.disable();
}

function WebPushSample_togglePushButton(active) {
    if ( active ) {
        this.subscribe_.disable();
        this.unsubscribe_.enable();
        this.setStatus(WebPushSample.STATE_PERMISSION, WebPushSample.STATUS_OK);
    } else {
        this.subscribe_.enable();
        this.unsubscribe_.disable();
        this.setStatus(WebPushSample.STATE_PERMISSION, WebPushSample.STATUS_NG);
    }
}

function WebPushSample_setStatus(index, state) {
    if ( ! this.states_[index] ) {
        return;
    }

    var element = this.states_[index];
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

function WebPushSample_sendPush(payload) {
    var post = {
        "endpoint": this.subscription_.endpoint,
        "p256dh":   Util.encodeURLBase64(this.subscription_.getKey("p256dh")),
        "auth":     Util.encodeURLBase64(this.subscription_.getKey("auth")),
        "payload":  payload
    };

    fetch(this.server_ + "/push", {
        method: "POST",
        body: JSON.stringify(post)
    }).then(function(response) {
        if ( ! response.ok ) {
            return this.log("Push response failed: " + response.status + " / " + response.statusText);
        }
        this.log("Send push succeed");
    });
}

function WebPushSample_handleRegisterServiceWorker() {
    this.setStatus(WebPushSample.STATE_SERVICEWORKER, WebPushSample.STATUS_OK);
    if ( Notification.permission === WebPushSample.PERMISSION_GRANTED ) {
        this.log("Notification has already granted");
        this.togglePushButton(true);
        return;
    }

    this.log("Notification permission request");
    Notification.requestPermission(function(permission) {
        if ( permission !== WebPushSample.PERMISSION_GRANTED ) {
            return;
        }
        this.log("Notification granted");
        this.togglePushButton(true);
    }.bind(this));
}

function WebPushSample_handleEvent(evt) {
    switch ( evt.target ) {
        // Boot ServiceWorker
        case this.register_.element():
            this.log("Boot serviceworker...");
            navigator.ServiceWorker.register("./ServiceWorker.js", {scope: "./"})
            .then(this.handleRegisterServiceWorker.bind(this));
            break;
        // Push Subscribe
        case this.subscribe_.element():
            if ( Notification.permission === WebPushSample.PERMISSION_DENIED ) {
                this.log("Disabled push", WebPushSample.LOGLEVEL_ERROR);
                this.togglePushButton(false);
                return;
            }

            navigator.serviceWorker.ready.then(this.subscribe.bind(this));
            break;
        // Push Unsubscribe
        case this.unsubscribe_.element():
            if ( ! this.subscription_ ) {
                return;
            }

            navigator.serviceWorker.ready.then(this.unsubscribe.bind(this));
            break;
        // Send Push
        case this.send_.element():
            var payload = this.payload_.value();
            if ( payload === "" ) {
                return;
            }

            this.sendPush(payload);
            break;
    }
}
})();
