self.addEventListener("fetch", function(event) {
    console.log(event);
});

self.addEventListener("push", function(evt) {
    evt.waitUntil(
        self.registration.showNotification("Hello", {
            icon: "/push.png",
            body: evt.data.text(),
            tag: "Notification"
        })
    );
});

self.addEventListener("notificationclick", function(evt) {
    console.log(evt);
    evt.notification.close();

    evt.waitUntil(
        clients.matchAll({ type: "window" }).then(function(evt) {
            var path = location.pathname.split("/")
            path.pop();
            path = location.protocol + "//" + location.host + path.join("/") + "/";
            evt.forEach(function(e) {
                if ( ((e.url === path) || (e.url === path + "index.html") ) && "focus" in e ) {
                    return e.focus();
                }
            });
            if ( clients.openWindow ) {
                return clients.openWindow("./");
            }
        })
    );

});
