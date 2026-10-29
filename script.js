const form = document.getElementById('loginForm');
const message = document.getElementById('message');
const button = form.querySelector('button');

form.addEventListener('submit', async function (event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    if (!username || !password) {
        message.textContent = 'Please fill in both fields.';
        return;
    }
    button.disabled = true;
    message.textContent = 'Checking...';
    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const result = await response.json();
        message.textContent = result.message;
        if (response.ok) window.location.href = '/welcome';
    } catch (error) {
        message.textContent = 'Cannot reach the server. Open this page at http://127.0.0.1:5000.';
    } finally {
        button.disabled = false;
    }
});
