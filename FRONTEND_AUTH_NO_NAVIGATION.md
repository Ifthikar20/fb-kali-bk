# Frontend Authentication - API Integration Only

Authentication code without navigation - your frontend handles redirects.

---

## Login Function (No Navigation)

```javascript
// Login function - returns success/error, no redirect
async function login(username, password) {
  try {
    const response = await fetch('http://localhost:8000/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: username,
        password: password
      })
    });

    if (!response.ok) {
      const error = await response.json();
      return {
        success: false,
        error: error.detail || 'Login failed'
      };
    }

    const data = await response.json();

    // Store authentication data
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('user_id', data.user_id);
    localStorage.setItem('username', data.username);
    localStorage.setItem('organization_id', data.organization_id);

    return {
      success: true,
      data: data
    };

  } catch (error) {
    console.error('Login error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Usage in your login form:
async function handleLoginSubmit(event) {
  event.preventDefault();

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const result = await login(username, password);

  if (result.success) {
    // Your frontend handles navigation
    console.log('Login successful:', result.data);
    // You can now navigate wherever you want
  } else {
    // Show error in your UI
    console.error('Login failed:', result.error);
    alert(result.error);
  }
}
```

---

## Register Function (No Navigation)

```javascript
// Register function - returns success/error, no redirect
async function register(username, email, password, fullName, organizationId) {
  try {
    const response = await fetch('http://localhost:8000/api/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: username,
        email: email,
        password: password,
        full_name: fullName || undefined,
        organization_id: organizationId
      })
    });

    if (!response.ok) {
      const error = await response.json();
      return {
        success: false,
        error: error.detail || 'Registration failed'
      };
    }

    const data = await response.json();

    // Store authentication data
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('user_id', data.user_id);
    localStorage.setItem('username', data.username);
    localStorage.setItem('organization_id', data.organization_id);

    return {
      success: true,
      data: data
    };

  } catch (error) {
    console.error('Registration error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Usage in your register form:
async function handleRegisterSubmit(event) {
  event.preventDefault();

  const username = document.getElementById('username').value;
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const fullName = document.getElementById('fullName').value;
  const organizationId = document.getElementById('organizationId').value;

  const result = await register(username, email, password, fullName, organizationId);

  if (result.success) {
    // Your frontend handles navigation
    console.log('Registration successful:', result.data);
  } else {
    // Show error in your UI
    console.error('Registration failed:', result.error);
    alert(result.error);
  }
}
```

---

## Auth Helper Functions

```javascript
// Check if user is logged in
function isLoggedIn() {
  return localStorage.getItem('access_token') !== null;
}

// Get auth token
function getAuthToken() {
  return localStorage.getItem('access_token');
}

// Get current user info
function getCurrentUser() {
  if (!isLoggedIn()) return null;

  return {
    user_id: localStorage.getItem('user_id'),
    username: localStorage.getItem('username'),
    organization_id: localStorage.getItem('organization_id'),
    token: getAuthToken()
  };
}

// Logout - clears storage, no redirect
function logout() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('user_id');
  localStorage.removeItem('username');
  localStorage.removeItem('organization_id');

  return { success: true };
}

// Fetch current user from API
async function fetchCurrentUser() {
  const token = getAuthToken();
  if (!token) return { success: false, error: 'Not authenticated' };

  try {
    const response = await fetch('http://localhost:8000/api/me', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      return { success: false, error: 'Failed to fetch user' };
    }

    const data = await response.json();
    return { success: true, data: data };

  } catch (error) {
    console.error('Error fetching user:', error);
    return { success: false, error: error.message };
  }
}
```

---

## Scan API Functions (With Auth)

```javascript
// Start a scan
async function startScan(targetUrl) {
  const token = getAuthToken();

  if (!token) {
    return { success: false, error: 'Not authenticated' };
  }

  try {
    const response = await fetch('http://localhost:8000/scan', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ target: targetUrl })
    });

    if (response.status === 401 || response.status === 403) {
      return { success: false, error: 'Authentication failed', needsLogin: true };
    }

    if (!response.ok) {
      const error = await response.json();
      return { success: false, error: error.detail || 'Scan failed' };
    }

    const data = await response.json();
    return { success: true, data: data };

  } catch (error) {
    console.error('Scan error:', error);
    return { success: false, error: error.message };
  }
}

// Get scan status
async function getScanStatus(jobId) {
  const token = getAuthToken();

  if (!token) {
    return { success: false, error: 'Not authenticated' };
  }

  try {
    const response = await fetch(`http://localhost:8000/scan/${jobId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (response.status === 401 || response.status === 403) {
      return { success: false, error: 'Authentication failed', needsLogin: true };
    }

    if (!response.ok) {
      return { success: false, error: 'Failed to get status' };
    }

    const data = await response.json();
    return { success: true, data: data };

  } catch (error) {
    console.error('Status error:', error);
    return { success: false, error: error.message };
  }
}

// Get agent graph
async function getAgentGraph(jobId) {
  const token = getAuthToken();

  if (!token) {
    return { success: false, error: 'Not authenticated' };
  }

  try {
    const response = await fetch(`http://localhost:8000/scan/${jobId}/agent-graph`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (response.status === 401 || response.status === 403) {
      return { success: false, error: 'Authentication failed', needsLogin: true };
    }

    if (!response.ok) {
      return { success: false, error: 'Failed to get agent graph' };
    }

    const data = await response.json();
    return { success: true, data: data };

  } catch (error) {
    console.error('Agent graph error:', error);
    return { success: false, error: error.message };
  }
}
```

---

## Usage Examples

### Login Example

```javascript
// In your login form handler
async function handleLogin() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const result = await login(username, password);

  if (result.success) {
    console.log('Logged in as:', result.data.username);
    // Your frontend decides where to navigate
    // router.push('/dashboard') or window.location.href = '/dashboard'
  } else {
    // Show error in your UI
    showError(result.error);
  }
}
```

### Register Example

```javascript
// In your register form handler
async function handleRegister() {
  const result = await register(username, email, password, fullName, orgId);

  if (result.success) {
    console.log('Account created:', result.data.username);
    // Your frontend decides where to navigate
  } else {
    showError(result.error);
  }
}
```

### Start Scan Example

```javascript
// In your scans page
async function handleStartScan() {
  const targetUrl = document.getElementById('targetUrl').value;

  const result = await startScan(targetUrl);

  if (result.success) {
    console.log('Scan started:', result.data.job_id);
    // Start polling for status
    pollStatus(result.data.job_id);
  } else {
    if (result.needsLogin) {
      // Your frontend decides what to do (show login modal, redirect, etc.)
      console.log('Need to login again');
    } else {
      showError(result.error);
    }
  }
}
```

### Poll Status Example

```javascript
// Poll for scan status
async function pollStatus(jobId) {
  const interval = setInterval(async () => {
    const result = await getScanStatus(jobId);

    if (result.success) {
      updateUI(result.data);

      // Stop polling when done
      if (result.data.status === 'completed' || result.data.status === 'failed') {
        clearInterval(interval);
        showFindings(result.data.findings);
      }
    } else {
      clearInterval(interval);
      if (result.needsLogin) {
        // Your frontend handles re-authentication
      } else {
        showError(result.error);
      }
    }
  }, 3000);
}
```

---

## Summary

All functions return `{ success: true/false, data/error, needsLogin? }` format:

```javascript
// Success response
{ success: true, data: { /* response data */ } }

// Error response
{ success: false, error: "Error message" }

// Auth error response
{ success: false, error: "Authentication failed", needsLogin: true }
```

Your frontend controls all navigation - these functions just handle the API calls and localStorage management.

---

## Key Points

✅ **No automatic redirects** - Your frontend decides where to navigate
✅ **Returns success/error objects** - Easy to handle in your UI
✅ **Token stored in localStorage** - Persists across page reloads
✅ **Auth errors include `needsLogin` flag** - You decide how to handle
✅ **All functions are async** - Use await or .then()

Just copy these functions and integrate them into your existing frontend routing/navigation system!
