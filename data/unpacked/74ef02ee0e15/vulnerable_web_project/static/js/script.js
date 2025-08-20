function showMessage(msg) {
    document.getElementById("message").innerHTML = msg;  // XSS 취약
}
