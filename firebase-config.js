// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyC_UFzib1fo5owX7UjDwrAByDWHqnTo9fw",
  authDomain: "socialhumon.firebaseapp.com",
  projectId: "socialhumon",
  storageBucket: "socialhumon.firebasestorage.app",
  messagingSenderId: "706743790961",
  appId: "1:706743790961:web:242f2ddc135ff9da619ad0",
  measurementId: "G-GCGN610W24"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);