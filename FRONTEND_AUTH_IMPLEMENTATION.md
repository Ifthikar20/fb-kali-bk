# Frontend Authentication Implementation Guide

Complete implementation of login/register flow for FetchBot.ai

---

## Step 1: Backend Setup

### Pull Latest Code and Rebuild Docker

```bash
cd /home/user/fb-kali-bk
git pull origin claude/implement-scan-api-endpoints-011CUwbKK2LMWLch6Ls5jezp

cd fetchbot-platform
docker-compose down
docker-compose up -d --build
```

Wait for startup, then verify:

```bash
# Check API is running
curl http://localhost:8000/health

# Should return: {"status":"healthy","platform":"FetchBot.ai"}
```

### Create Initial Organization (One-time Setup)

```bash
curl -X POST http://localhost:8000/api/organizations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Default Organization",
    "admin_email": "admin@example.com",
    "allowed_targets": []
  }'
```

**Save the `id` from the response!** You'll need this for user registration.

Example response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Default Organization",
  "api_key": "fb_live_...",
  "elastic_ip": "127.0.0.1",
  "mode": "local"
}
```

---

## Step 2: Frontend Implementation

### Option A: Vanilla JavaScript Implementation

#### 1. Login Page (login.html)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - FetchBot.ai</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        .error.show {
            display: block;
        }
        .register-link {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        .register-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        .register-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Welcome Back</h1>
        <p class="subtitle">Sign in to FetchBot.ai</p>

        <div id="error" class="error"></div>

        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>

            <button type="submit" id="loginBtn">Sign In</button>
        </form>

        <div class="register-link">
            Don't have an account? <a href="/register.html">Register here</a>
        </div>
    </div>

    <script>
        const API_URL = 'http://localhost:8000';

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            const loginBtn = document.getElementById('loginBtn');

            // Clear previous errors
            errorDiv.classList.remove('show');
            errorDiv.textContent = '';

            // Disable button
            loginBtn.disabled = true;
            loginBtn.textContent = 'Signing in...';

            try {
                const response = await fetch(`${API_URL}/api/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Login failed');
                }

                const data = await response.json();

                // Store authentication data
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('user_id', data.user_id);
                localStorage.setItem('username', data.username);
                localStorage.setItem('organization_id', data.organization_id);

                // Redirect to dashboard
                window.location.href = '/dashboard/scans';

            } catch (error) {
                console.error('Login error:', error);
                errorDiv.textContent = error.message;
                errorDiv.classList.add('show');

                // Re-enable button
                loginBtn.disabled = false;
                loginBtn.textContent = 'Sign In';
            }
        });
    </script>
</body>
</html>
```

#### 2. Register Page (register.html)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - FetchBot.ai</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .register-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        .error.show {
            display: block;
        }
        .success {
            background: #efe;
            color: #3c3;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        .success.show {
            display: block;
        }
        .login-link {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        .login-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        .login-link a:hover {
            text-decoration: underline;
        }
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 12px;
            margin-bottom: 20px;
            border-radius: 4px;
            font-size: 13px;
            color: #1976d2;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h1>Create Account</h1>
        <p class="subtitle">Join FetchBot.ai</p>

        <div class="info-box">
            <strong>Organization ID Required:</strong> Get your organization ID from your admin or create one via API.
        </div>

        <div id="error" class="error"></div>
        <div id="success" class="success"></div>

        <form id="registerForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>

            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required autocomplete="email">
            </div>

            <div class="form-group">
                <label for="fullName">Full Name (Optional)</label>
                <input type="text" id="fullName" name="fullName" autocomplete="name">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="new-password" minlength="8">
            </div>

            <div class="form-group">
                <label for="organizationId">Organization ID</label>
                <input type="text" id="organizationId" name="organizationId" required placeholder="e.g., 550e8400-e29b-41d4-a716-446655440000">
            </div>

            <button type="submit" id="registerBtn">Create Account</button>
        </form>

        <div class="login-link">
            Already have an account? <a href="/login.html">Sign in</a>
        </div>
    </div>

    <script>
        const API_URL = 'http://localhost:8000';

        // Pre-fill organization ID from URL parameter (optional)
        const urlParams = new URLSearchParams(window.location.search);
        const orgId = urlParams.get('org_id');
        if (orgId) {
            document.getElementById('organizationId').value = orgId;
        }

        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const fullName = document.getElementById('fullName').value;
            const password = document.getElementById('password').value;
            const organizationId = document.getElementById('organizationId').value;

            const errorDiv = document.getElementById('error');
            const successDiv = document.getElementById('success');
            const registerBtn = document.getElementById('registerBtn');

            // Clear previous messages
            errorDiv.classList.remove('show');
            successDiv.classList.remove('show');
            errorDiv.textContent = '';
            successDiv.textContent = '';

            // Disable button
            registerBtn.disabled = true;
            registerBtn.textContent = 'Creating account...';

            try {
                const response = await fetch(`${API_URL}/api/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username,
                        email,
                        password,
                        full_name: fullName || undefined,
                        organization_id: organizationId
                    })
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Registration failed');
                }

                const data = await response.json();

                // Store authentication data
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('user_id', data.user_id);
                localStorage.setItem('username', data.username);
                localStorage.setItem('organization_id', data.organization_id);

                // Show success message
                successDiv.textContent = 'Account created successfully! Redirecting...';
                successDiv.classList.add('show');

                // Redirect to dashboard after 1 second
                setTimeout(() => {
                    window.location.href = '/dashboard/scans';
                }, 1000);

            } catch (error) {
                console.error('Registration error:', error);
                errorDiv.textContent = error.message;
                errorDiv.classList.add('show');

                // Re-enable button
                registerBtn.disabled = false;
                registerBtn.textContent = 'Create Account';
            }
        });
    </script>
</body>
</html>
```

#### 3. Authentication Utility (auth.js)

Create this file to handle authentication across your app:

```javascript
// auth.js - Authentication utilities

const API_URL = 'http://localhost:8000';

// Check if user is logged in
function isLoggedIn() {
    return localStorage.getItem('access_token') !== null;
}

// Get auth token
function getAuthToken() {
    return localStorage.getItem('access_token');
}

// Get current user info from localStorage
function getCurrentUser() {
    if (!isLoggedIn()) return null;

    return {
        user_id: localStorage.getItem('user_id'),
        username: localStorage.getItem('username'),
        organization_id: localStorage.getItem('organization_id'),
        token: getAuthToken()
    };
}

// Logout user
function logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_id');
    localStorage.removeItem('username');
    localStorage.removeItem('organization_id');
    window.location.href = '/login.html';
}

// Fetch current user from API (with fresh data)
async function fetchCurrentUser() {
    const token = getAuthToken();
    if (!token) return null;

    try {
        const response = await fetch(`${API_URL}/api/me`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                logout();
                return null;
            }
            throw new Error('Failed to fetch user');
        }

        return await response.json();
    } catch (error) {
        console.error('Error fetching user:', error);
        return null;
    }
}

// Make authenticated API request
async function apiRequest(url, options = {}) {
    const token = getAuthToken();

    if (!token) {
        throw new Error('Not authenticated');
    }

    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers
    };

    const response = await fetch(`${API_URL}${url}`, {
        ...options,
        headers
    });

    // Handle auth errors
    if (response.status === 401 || response.status === 403) {
        logout();
        throw new Error('Session expired');
    }

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Request failed' }));
        throw new Error(error.detail || 'Request failed');
    }

    return response.json();
}

// Protect page - redirect to login if not authenticated
function protectPage() {
    if (!isLoggedIn()) {
        window.location.href = '/login.html';
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        isLoggedIn,
        getAuthToken,
        getCurrentUser,
        logout,
        fetchCurrentUser,
        apiRequest,
        protectPage,
        API_URL
    };
}
```

#### 4. Scans Page Implementation

Update your scans page to use authentication:

```javascript
// At the top of your scans page
protectPage(); // Redirect to login if not authenticated

const user = getCurrentUser();
console.log('Logged in as:', user.username);

// Start a scan
async function startScan(targetUrl) {
    try {
        const data = await apiRequest('/scan', {
            method: 'POST',
            body: JSON.stringify({ target: targetUrl })
        });

        console.log('Scan started:', data);
        return data.job_id;

    } catch (error) {
        console.error('Scan error:', error);
        alert('Failed to start scan: ' + error.message);
    }
}

// Poll for scan status
async function pollScanStatus(jobId) {
    try {
        const data = await apiRequest(`/scan/${jobId}`);
        return data;
    } catch (error) {
        console.error('Status error:', error);
        return null;
    }
}

// Get agent graph
async function getAgentGraph(jobId) {
    try {
        const data = await apiRequest(`/scan/${jobId}/agent-graph`);
        return data;
    } catch (error) {
        console.error('Agent graph error:', error);
        return null;
    }
}
```

---

## Step 3: Testing the Flow

### Test Registration

1. Go to `http://localhost:8080/register.html`
2. Fill in the form with your organization ID
3. Submit
4. You should be redirected to `/dashboard/scans` and logged in

### Test Login

1. Go to `http://localhost:8080/login.html`
2. Enter credentials
3. Submit
4. You should be redirected to `/dashboard/scans`

### Test Scan API

```javascript
// In browser console on scans page:
const jobId = await startScan('https://example.com');
const status = await pollScanStatus(jobId);
console.log(status);
```

---

## Complete API Reference

### Authentication Endpoints

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---------------|
| `/api/register` | POST | Create new user | No |
| `/api/login` | POST | Login and get JWT | No |
| `/api/me` | GET | Get current user | Yes (JWT) |

### Scan Endpoints

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---------------|
| `/scan` | POST | Start scan | Yes (JWT or API key) |
| `/scan/{job_id}` | GET | Get scan status | Yes (JWT or API key) |
| `/scan/{job_id}/agent-graph` | GET | Get agent hierarchy | Yes (JWT or API key) |

---

## Troubleshooting

### "404 Not Found" on /api/register

**Fix:** Rebuild Docker container
```bash
cd fetchbot-platform
docker-compose down
docker-compose up -d --build
```

### "401 Unauthorized" on protected endpoints

**Fix:** Check localStorage has `access_token`
```javascript
console.log(localStorage.getItem('access_token'));
```

### CORS errors

**Fix:** Already configured! Backend allows `localhost:8080`

---

## Next Steps

1. ✅ Rebuild Docker container
2. ✅ Create organization and get ID
3. ✅ Add login.html and register.html to your frontend
4. ✅ Include auth.js in your pages
5. ✅ Update scans page to use `apiRequest()` function
6. ✅ Test the complete flow

Your authentication is now complete! 🚀
