document.addEventListener("DOMContentLoaded", function() {
    const loginForm = document.getElementById("loginForm");
    const commandForm = document.getElementById("commandForm");

    if (loginForm) {
        loginForm.addEventListener("submit", function(event) {
            const username = document.getElementById("username").value.trim();
            const password = document.getElementById("password").value.trim();

            if (!username || !password) {
                event.preventDefault();
                alert("Please enter both username and password.");
            }
        });
    }

    if (commandForm) {
        commandForm.addEventListener("submit", function(event) {
            const ip = document.getElementById("ip").value.trim();
            const duration = document.getElementById("duration").value.trim();
            const port = document.getElementById("port").value.trim();

            if (!ip || !duration || !port) {
                event.preventDefault();
                alert("All command parameters are required.");
            }
        });
    }
});
