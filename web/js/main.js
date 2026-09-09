const responseBox = document.getElementById('responseBox');
const sessionStatus = document.getElementById('sessionStatus');
const csrfTokenInput = document.getElementById('csrfTokenInput');

const appState = {
  loggedIn: false,
};

function setResponse(message, type = 'info') {
  responseBox.className = 'response';
  if (type === 'success') responseBox.classList.add('success');
  if (type === 'error') responseBox.classList.add('error');
  responseBox.textContent = message;
}

function clearResponse() {
  responseBox.className = 'response';
  responseBox.textContent = '';
}

function readCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return '';
}

function updateSessionStatus() {
  const csrfToken = readCookie('csrf_token');
  const isLoggedIn = appState.loggedIn && Boolean(csrfToken);

  sessionStatus.textContent = isLoggedIn ? 'logged in' : 'logged out';
  sessionStatus.classList.toggle('out', !isLoggedIn);
  sessionStatus.classList.toggle('in', isLoggedIn);
  csrfTokenInput.value = csrfToken || '';
}

function setLoggedInState(loggedIn) {
  appState.loggedIn = loggedIn;
  updateSessionStatus();
}

document.querySelectorAll('.tab-button').forEach((button) => {
  button.addEventListener('click', () => {
    clearResponse();

    document.querySelectorAll('.tab-button').forEach((btn) => btn.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach((panel) => panel.classList.add('hidden'));

    button.classList.add('active');
    document.getElementById(`${button.dataset.tab}Tab`).classList.remove('hidden');
  });
});

document.getElementById('registerForm').addEventListener('submit', async (event) => {
  event.preventDefault();

  const formData = new FormData(event.target);
  const body = new URLSearchParams(formData).toString();

  try {
    const response = await fetch('/v1/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    const text = await response.text();
    setResponse(text, response.ok ? 'success' : 'error');
    setLoggedInState(false);
  } catch (error) {
    setResponse(`Request failed: ${error.message}`, 'error');
  }
});

document.getElementById('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();

  if (appState.loggedIn || readCookie('session_token') || readCookie('csrf_token')) {
    setResponse('User is already logged in. Please log out before logging in again.', 'error');
    return;
  }

  const formData = new FormData(event.target);
  const body = new URLSearchParams(formData).toString();

  try {
    const response = await fetch('/v1/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      credentials: 'same-origin',
    });

    const text = await response.text();
    setResponse(text, response.ok ? 'success' : 'error');
    setLoggedInState(response.ok);
  } catch (error) {
    setResponse(`Request failed: ${error.message}`, 'error');
    setLoggedInState(false);
  }
});

document.getElementById('logoutButton').addEventListener('click', async () => {
  const username = document.querySelector('#loginForm input[name="username"]').value.trim();
  const csrfToken = readCookie('csrf_token');

  try {
    const response = await fetch('/v1/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrfToken },
      body: new URLSearchParams({ username }).toString(),
      credentials: 'same-origin',
    });

    const text = await response.text();
    setResponse(text, response.ok ? 'success' : 'error');
    setLoggedInState(false);
  } catch (error) {
    setResponse(`Request failed: ${error.message}`, 'error');
    setLoggedInState(false);
  }
});

document.getElementById('protectedForm').addEventListener('submit', async (event) => {
  event.preventDefault();

  const username = document.querySelector('#protectedForm input[name="username"]').value.trim();
  const csrfToken = readCookie('csrf_token');

  try {
    const response = await fetch('/v1/protected', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRF-Token': csrfToken,
      },
      body: new URLSearchParams({ username }).toString(),
      credentials: 'same-origin',
    });

    const text = await response.text();
    setResponse(text, response.ok ? 'success' : 'error');
    setLoggedInState(response.ok);
  } catch (error) {
    setResponse(`Request failed: ${error.message}`, 'error');
    setLoggedInState(false);
  }
});

updateSessionStatus();
