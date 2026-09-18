const responseBox = document.getElementById('responseBox');
const sessionStatus = document.getElementById('sessionStatus');
const csrfTokenInput = document.getElementById('csrfTokenInput');

const MIN_CREDENTIAL_LENGTH = 8;
const MAX_USERNAME_LENGTH = 32;
const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

const appState = {
  loggedIn: false,
  username: '',
};

function validateUsername(username) {
  const trimmed = (username || '').trim();

  if (!trimmed) return 'username is required';
  if (trimmed.length < MIN_CREDENTIAL_LENGTH) return `username must be at least ${MIN_CREDENTIAL_LENGTH} characters long`;
  if (trimmed.length > MAX_USERNAME_LENGTH) return `username must be at most ${MAX_USERNAME_LENGTH} characters long`;
  if (!USERNAME_PATTERN.test(trimmed)) return 'username contains unsupported characters';

  return '';
}

function validatePassword(password) {
  const value = password || '';

  if (!value) return 'password is required';
  if (value.length < MIN_CREDENTIAL_LENGTH) return `password must be at least ${MIN_CREDENTIAL_LENGTH} characters long`;

  return '';
}

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

function readUserCookie(username, prefix) {
  if (!username) return '';
  return readCookie(`${prefix}_${username}`);
}

function updateSessionStatus() {
  const username = appState.username || document.querySelector('#loginForm input[name="username"]')?.value.trim() || '';
  const csrfToken = username ? readUserCookie(username, 'csrf_token') : '';
  const isLoggedIn = appState.loggedIn && Boolean(csrfToken);

  sessionStatus.textContent = isLoggedIn ? 'logged in' : 'logged out';
  sessionStatus.classList.toggle('out', !isLoggedIn);
  sessionStatus.classList.toggle('in', isLoggedIn);
  csrfTokenInput.value = csrfToken || '';
}

function setLoggedInState(loggedIn, username = '') {
  appState.loggedIn = loggedIn;
  appState.username = loggedIn ? username : '';
  updateSessionStatus();
}

function getActiveUsername(formSelector) {
  const input = document.querySelector(formSelector);
  const typedUsername = input ? input.value.trim() : '';
  return typedUsername || appState.username || '';
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

  if (!event.target.checkValidity()) {
    event.target.reportValidity();
    return;
  }

  const formData = new FormData(event.target);
  const username = (formData.get('username') || '').toString();
  const password = (formData.get('password') || '').toString();

  const usernameError = validateUsername(username);
  if (usernameError) {
    setResponse(usernameError, 'error');
    return;
  }

  const passwordError = validatePassword(password);
  if (passwordError) {
    setResponse(passwordError, 'error');
    return;
  }

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

  if (!event.target.checkValidity()) {
    event.target.reportValidity();
    return;
  }

  const formData = new FormData(event.target);
  const username = (formData.get('username') || '').toString();
  const password = (formData.get('password') || '').toString();

  const usernameError = validateUsername(username);
  if (usernameError) {
    setResponse(usernameError, 'error');
    return;
  }

  const passwordError = validatePassword(password);
  if (passwordError) {
    setResponse(passwordError, 'error');
    return;
  }

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
    setLoggedInState(response.ok, response.ok ? username.trim() : '');
  } catch (error) {
    setResponse(`Request failed: ${error.message}`, 'error');
    setLoggedInState(false, '');
  }
});

document.getElementById('logoutButton').addEventListener('click', async () => {
  const username = getActiveUsername('#loginForm input[name="username"]');
  const usernameError = validateUsername(username);
  if (usernameError) {
    setResponse(usernameError, 'error');
    return;
  }

  const csrfToken = readUserCookie(username.trim(), 'csrf_token');

  try {
    const response = await fetch('/v1/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Csrf-Token': csrfToken },
      body: new URLSearchParams({ username: username.trim() }).toString(),
      credentials: 'same-origin',
    });

    const text = await response.text();
    setResponse(text, response.ok ? 'success' : 'error');
    setLoggedInState(false, '');
  } catch (error) {
    setResponse(`Request failed: ${error.message}`, 'error');
    setLoggedInState(false, '');
  }
});

document.getElementById('protectedForm').addEventListener('submit', async (event) => {
  event.preventDefault();

  const form = event.target;
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }

  const username = getActiveUsername('#protectedForm input[name="username"]');
  const usernameError = validateUsername(username);
  if (usernameError) {
    setResponse(usernameError, 'error');
    return;
  }

  const csrfToken = readUserCookie(username.trim(), 'csrf_token');

  try {
    const response = await fetch('/v1/protected', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Csrf-Token': csrfToken,
      },
      body: new URLSearchParams({ username: username.trim() }).toString(),
      credentials: 'same-origin',
    });

    const text = await response.text();
    setResponse(text, response.ok ? 'success' : 'error');
    setLoggedInState(response.ok, response.ok ? username.trim() : '');
  } catch (error) {
    setResponse(`Request failed: ${error.message}`, 'error');
    setLoggedInState(false, '');
  }
});

updateSessionStatus();
