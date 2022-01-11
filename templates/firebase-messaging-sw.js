importScripts('https://www.gstatic.com/firebasejs/9.6.1/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/9.6.1/firebase-messaging.js');

var firebaseConfig = { 
	apiKey: "AIzaSyDtbmlJ19oBUOm5dwpzPmtqycs6SrN70eY", 
	authDomain: "bookcounter-c2b0f.firebaseapp.com", 
	projectId: "bookcounter-c2b0f", 
	databaseURL: "https://console.firebase.google.com/project/bookcounter-c2b0f/overview", 
	storageBucket: "bookcounter-c2b0f.appspot.com", 
	messagingSenderId: "218818796464", 
	appId: "1:218818796464:web:76690912bb7199c6595475",
	measurementId:"G-PTFEEJXB3J", 
	}; 
firebase.initializeApp(firebaseConfig);
const messaging = firebase.messaging();

messaging.setBackgroundMessageHandler(function (payload) {
    console.log('[firebase-messaging-sw.js] Received background message ', payload);
    // Customize notification here
    const notificationTitle = 'Background Message Title';
    const notificationOptions = {
      body:notification.body,
      icon: notification.icon_url,
    };
    
    return self.registration.showNotification(notificationTitle,
        notificationOptions);

});

