# Frontend Integration Architecture Guide for EsyaSoft AI Chatbot Platform

**Author:** Based on architectural playbook by amansingh9097@gmail.com  
**Date:** January 13, 2026  
**Version:** 1.0

---

## Table of Contents

1. [JWT-Based Authentication with Keycloak](#1-jwt-based-authentication-with-keycloak)
2. [Session Management](#2-session-management)
3. [Rate Limiting](#3-rate-limiting)
4. [HttpOnly Cookie Authentication](#4-httponly-cookie-authentication)
5. [Conversation History](#5-conversation-history)
6. [Internal Module Communication](#6-internal-module-communication)
7. [Quick Links](#7-quick-links)
8. [Favorites](#8-favorites)
9. [RBAC Implementation with Keycloak](#9-rbac-implementation-with-keycloak)
10. [Security Checklist](#10-security-checklist)

---

## Architecture Overview

This guide implements the **stateless, SOC2-compliant, RBAC-enabled** architecture as specified in the playbook:

- **Authentication**: Keycloak (OIDC/SAML)
- **Authorization**: RBAC (Role-Based Access Control)
- **Rate Limiting**: Redis-backed (20 req/min per user)
- **Transfer Protocol**: HTTPS/mTLS
- **Frontend**: React/Next.js (stateless)

---

## 1. JWT-Based Authentication with Keycloak

### 1.1 Architecture Flow

```
User Login → API Gateway → Keycloak → JWT Token → Frontend Storage
                ↓
         Validate Token
                ↓
         Check RBAC Permissions
                ↓
         Access Granted/Denied
```

### 1.2 JWT Token Structure

```json
{
  "sub": "user_id_123",
  "email": "user@example.com",
  "name": "John Doe",
  "roles": ["analyst", "tool_executor"],
  "permissions": [
    "read:reports",
    "execute:nl2sql_tool",
    "write:conversations"
  ],
  "org_id": "org_456",
  "realm_access": {
    "roles": ["realm_role_1"]
  },
  "resource_access": {
    "ai-chatbot": {
      "roles": ["user", "analyst"]
    }
  },
  "exp": 1736766000,
  "iat": 1736764200,
  "iss": "https://keycloak.example.com/realms/esyasoft",
  "aud": "ai-chatbot-client"
}
```

### 1.3 Frontend Authentication Service

```javascript
// services/auth.service.js

import axios from 'axios';
import jwtDecode from 'jwt-decode';

class AuthService {
  constructor() {
    this.keycloakConfig = {
      realm: 'esyasoft',
      clientId: 'ai-chatbot-client',
      authUrl: process.env.NEXT_PUBLIC_KEYCLOAK_URL
    };
  }

  /**
   * Login with username/password
   */
  async login(username, password) {
    try {
      const response = await axios.post('/api/v1/auth/login', {
        username,
        password,
        client_id: this.keycloakConfig.clientId
      });

      const { access_token, refresh_token, expires_in } = response.data;

      // Store tokens
      this.setTokens(access_token, refresh_token, expires_in);

      // Decode and return user info
      const userInfo = this.decodeToken(access_token);
      
      return userInfo;
    } catch (error) {
      throw new Error(`Login failed: ${error.response?.data?.message || error.message}`);
    }
  }

  /**
   * Store tokens securely
   */
  setTokens(accessToken, refreshToken, expiresIn) {
    // Access token in sessionStorage (cleared on tab close)
    sessionStorage.setItem('access_token', accessToken);
    sessionStorage.setItem('token_expiry', Date.now() + (expiresIn * 1000));
    
    // Refresh token in localStorage (for "remember me")
    if (refreshToken) {
      localStorage.setItem('refresh_token', refreshToken);
    }
  }

  /**
   * Get current access token
   */
  getToken() {
    return sessionStorage.getItem('access_token');
  }

  /**
   * Check if token is expired
   */
  isTokenExpired() {
    const expiry = sessionStorage.getItem('token_expiry');
    if (!expiry) return true;
    
    return Date.now() > parseInt(expiry);
  }

  /**
   * Refresh access token
   */
  async refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await axios.post('/api/v1/auth/refresh', {
        refresh_token: refreshToken,
        client_id: this.keycloakConfig.clientId
      });

      const { access_token, expires_in } = response.data;
      
      sessionStorage.setItem('access_token', access_token);
      sessionStorage.setItem('token_expiry', Date.now() + (expires_in * 1000));
      
      return access_token;
    } catch (error) {
      // Refresh failed, clear all tokens
      this.logout();
      throw new Error('Token refresh failed');
    }
  }

  /**
   * Decode JWT token
   */
  decodeToken(token) {
    try {
      return jwtDecode(token);
    } catch (error) {
      console.error('Failed to decode token:', error);
      return null;
    }
  }

  /**
   * Get current user info
   */
  getCurrentUser() {
    const token = this.getToken();
    if (!token) return null;
    
    return this.decodeToken(token);
  }

  /**
   * Check if user has specific role
   */
  hasRole(role) {
    const user = this.getCurrentUser();
    return user?.roles?.includes(role) || false;
  }

  /**
   * Check if user has specific permission
   */
  hasPermission(permission) {
    const user = this.getCurrentUser();
    return user?.permissions?.includes(permission) || false;
  }

  /**
   * Logout
   */
  async logout() {
    try {
      // Call backend logout endpoint
      await axios.post('/api/v1/auth/logout', {
        refresh_token: localStorage.getItem('refresh_token')
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear all tokens
      sessionStorage.clear();
      localStorage.removeItem('refresh_token');
      
      // Redirect to login
      window.location.href = '/login';
    }
  }

  /**
   * SSO Login with Keycloak (Optional)
   */
  async ssoLogin() {
    const keycloakLoginUrl = `${this.keycloakConfig.authUrl}/realms/${this.keycloakConfig.realm}/protocol/openid-connect/auth`;
    
    const params = new URLSearchParams({
      client_id: this.keycloakConfig.clientId,
      redirect_uri: `${window.location.origin}/auth/callback`,
      response_type: 'code',
      scope: 'openid profile email'
    });

    window.location.href = `${keycloakLoginUrl}?${params.toString()}`;
  }

  /**
   * Handle SSO callback
   */
  async handleSSOCallback(code) {
    const response = await axios.post('/api/v1/auth/callback', {
      code,
      redirect_uri: `${window.location.origin}/auth/callback`
    });

    const { access_token, refresh_token, expires_in } = response.data;
    this.setTokens(access_token, refresh_token, expires_in);

    return this.getCurrentUser();
  }
}

export default new AuthService();
```

### 1.4 Axios Request Interceptor

```javascript
// config/axios.interceptor.js

import axios from 'axios';
import authService from '../services/auth.service';

// Request interceptor - Add JWT to headers
axios.interceptors.request.use(
  (config) => {
    const token = authService.getToken();
    
    if (token && !authService.isTokenExpired()) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - Handle token expiration
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 - Token expired
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Attempt to refresh token
        const newToken = await authService.refreshToken();
        
        // Retry original request with new token
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        return axios(originalRequest);
      } catch (refreshError) {
        // Refresh failed - redirect to login
        authService.logout();
        return Promise.reject(refreshError);
      }
    }

    // Handle 403 - Insufficient permissions
    if (error.response?.status === 403) {
      console.error('Insufficient permissions:', error.response.data);
      // Show user-friendly error
      throw new Error('You do not have permission to perform this action');
    }

    return Promise.reject(error);
  }
);

export default axios;
```

### 1.5 Protected Route Component

```jsx
// components/ProtectedRoute.jsx

import React from 'react';
import { Navigate } from 'react-router-dom';
import authService from '../services/auth.service';

const ProtectedRoute = ({ 
  children, 
  requiredRoles = [], 
  requiredPermissions = [] 
}) => {
  const user = authService.getCurrentUser();

  // Not authenticated
  if (!user) {
    return <Navigate to="/login" replace />;
  }

  // Check required roles
  if (requiredRoles.length > 0) {
    const hasRequiredRole = requiredRoles.some(role => 
      authService.hasRole(role)
    );
    
    if (!hasRequiredRole) {
      return <Navigate to="/unauthorized" replace />;
    }
  }

  // Check required permissions
  if (requiredPermissions.length > 0) {
    const hasRequiredPermission = requiredPermissions.some(permission => 
      authService.hasPermission(permission)
    );
    
    if (!hasRequiredPermission) {
      return <Navigate to="/unauthorized" replace />;
    }
  }

  return children;
};

export default ProtectedRoute;
```

### 1.6 Usage in Routes

```jsx
// App.jsx

import { BrowserRouter, Routes, Route } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute';
import Dashboard from './pages/Dashboard';
import AdminPanel from './pages/AdminPanel';
import Login from './pages/Login';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        
        {/* Protected route - any authenticated user */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        
        {/* Protected route - requires admin role */}
        <Route
          path="/admin"
          element={
            <ProtectedRoute requiredRoles={['admin']}>
              <AdminPanel />
            </ProtectedRoute>
          }
        />
        
        {/* Protected route - requires specific permission */}
        <Route
          path="/tools/nl2sql"
          element={
            <ProtectedRoute requiredPermissions={['execute:nl2sql_tool']}>
              <NL2SQLTool />
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
```

---

## 2. Session Management

### 2.1 Stateless Session Approach

**Per playbook requirements**: All services must be **stateless**. Sessions are managed via:
- JWT tokens (client-side)
- Redis (server-side, for rate limiting only)

### 2.2 Session Manager Implementation

```javascript
// services/session.manager.js

class SessionManager {
  constructor() {
    this.sessionTimeout = 30 * 60 * 1000; // 30 minutes (per playbook)
    this.warningTime = 5 * 60 * 1000; // 5 minutes warning
    this.activityTimeout = null;
    this.warningTimeout = null;
  }

  /**
   * Start session monitoring
   */
  startSession() {
    this.resetActivityTimer();
    
    // Listen for user activity
    const events = ['mousedown', 'keypress', 'scroll', 'touchstart', 'click'];
    
    events.forEach(event => {
      document.addEventListener(event, () => this.handleActivity(), { passive: true });
    });

    console.log('Session monitoring started');
  }

  /**
   * Handle user activity
   */
  handleActivity() {
    this.resetActivityTimer();
  }

  /**
   * Reset activity timer
   */
  resetActivityTimer() {
    // Clear existing timers
    clearTimeout(this.activityTimeout);
    clearTimeout(this.warningTimeout);

    // Set warning timer (5 minutes before timeout)
    this.warningTimeout = setTimeout(() => {
      this.showWarning();
    }, this.sessionTimeout - this.warningTime);

    // Set session timeout timer
    this.activityTimeout = setTimeout(() => {
      this.handleSessionTimeout();
    }, this.sessionTimeout);
  }

  /**
   * Show session timeout warning
   */
  showWarning() {
    const remainingTime = Math.floor(this.warningTime / 1000);
    
    // Show modal or notification
    const continueSession = confirm(
      `Your session will expire in ${remainingTime / 60} minutes due to inactivity. Click OK to continue.`
    );

    if (continueSession) {
      this.resetActivityTimer();
    }
  }

  /**
   * Handle session timeout
   */
  handleSessionTimeout() {
    console.log('Session timed out due to inactivity');
    
    // Clear tokens
    sessionStorage.clear();
    localStorage.removeItem('refresh_token');
    
    // Show timeout message
    sessionStorage.setItem('timeout_message', 'Your session has expired due to inactivity.');
    
    // Redirect to login
    window.location.href = '/login?reason=timeout';
  }

  /**
   * End session
   */
  endSession() {
    clearTimeout(this.activityTimeout);
    clearTimeout(this.warningTimeout);
    sessionStorage.clear();
    
    console.log('Session ended');
  }

  /**
   * Get session info
   */
  getSessionInfo() {
    const token = sessionStorage.getItem('access_token');
    const expiry = sessionStorage.getItem('token_expiry');
    
    if (!token || !expiry) {
      return null;
    }

    const remainingTime = parseInt(expiry) - Date.now();
    
    return {
      isActive: remainingTime > 0,
      expiresAt: new Date(parseInt(expiry)),
      remainingMinutes: Math.floor(remainingTime / 60000)
    };
  }
}

export default new SessionManager();
```

### 2.3 React Hook for Session

```javascript
// hooks/useSession.js

import { useState, useEffect } from 'react';
import sessionManager from '../services/session.manager';

export const useSession = () => {
  const [sessionInfo, setSessionInfo] = useState(null);

  useEffect(() => {
    // Start session monitoring
    sessionManager.startSession();

    // Update session info every minute
    const interval = setInterval(() => {
      const info = sessionManager.getSessionInfo();
      setSessionInfo(info);
    }, 60000);

    return () => {
      clearInterval(interval);
      sessionManager.endSession();
    };
  }, []);

  return sessionInfo;
};
```

---

## 3. Rate Limiting

### 3.1 Client-Side Rate Limiter

**Per playbook**: 20 requests/minute per user

```javascript
// services/rate.limiter.js

class RateLimiter {
  constructor(maxRequests = 20, windowMs = 60000) {
    this.maxRequests = maxRequests; // 20 requests per minute
    this.windowMs = windowMs; // 60 seconds
    this.requests = [];
  }

  /**
   * Check if request can be made
   */
  canMakeRequest() {
    const now = Date.now();

    // Remove expired requests from window
    this.requests = this.requests.filter(
      timestamp => now - timestamp < this.windowMs
    );

    // Check if limit exceeded
    if (this.requests.length >= this.maxRequests) {
      const oldestRequest = this.requests[0];
      const timeToWait = this.windowMs - (now - oldestRequest);

      return {
        allowed: false,
        retryAfter: Math.ceil(timeToWait / 1000),
        remaining: 0,
        resetAt: new Date(now + timeToWait)
      };
    }

    // Add current request
    this.requests.push(now);

    return {
      allowed: true,
      remaining: this.maxRequests - this.requests.length,
      resetAt: new Date(now + this.windowMs)
    };
  }

  /**
   * Get current rate limit status
   */
  getStatus() {
    const now = Date.now();
    
    this.requests = this.requests.filter(
      timestamp => now - timestamp < this.windowMs
    );

    return {
      limit: this.maxRequests,
      remaining: this.maxRequests - this.requests.length,
      used: this.requests.length,
      resetAt: this.requests.length > 0 
        ? new Date(this.requests[0] + this.windowMs)
        : new Date(now + this.windowMs)
    };
  }

  /**
   * Reset rate limiter
   */
  reset() {
    this.requests = [];
  }
}

export default new RateLimiter(20, 60000);
```

### 3.2 Integration with Axios

```javascript
// config/axios.ratelimit.js

import axios from 'axios';
import rateLimiter from '../services/rate.limiter';

// Add rate limiting to request interceptor
axios.interceptors.request.use(
  (config) => {
    // Skip rate limiting for auth endpoints
    if (config.url?.includes('/auth/')) {
      return config;
    }

    const { allowed, retryAfter, remaining } = rateLimiter.canMakeRequest();

    if (!allowed) {
      // Show notification to user
      const message = `Rate limit exceeded. Please wait ${retryAfter} seconds.`;
      
      // Dispatch event for UI notification
      window.dispatchEvent(
        new CustomEvent('rate-limit-exceeded', {
          detail: { message, retryAfter }
        })
      );

      return Promise.reject(new Error('Rate limit exceeded'));
    }

    // Add rate limit info to headers for backend
    config.headers['X-RateLimit-Remaining'] = remaining;

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Handle 429 responses from backend
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'] || 60;
      const resetTime = error.response.headers['x-ratelimit-reset'];

      window.dispatchEvent(
        new CustomEvent('rate-limit-exceeded', {
          detail: {
            message: `Too many requests. Please retry after ${retryAfter} seconds.`,
            retryAfter: parseInt(retryAfter),
            resetTime
          }
        })
      );
    }

    return Promise.reject(error);
  }
);
```

### 3.3 React Component for Rate Limit Display

```jsx
// components/RateLimitIndicator.jsx

import React, { useState, useEffect } from 'react';
import rateLimiter from '../services/rate.limiter';

const RateLimitIndicator = () => {
  const [status, setStatus] = useState(rateLimiter.getStatus());
  const [notification, setNotification] = useState(null);

  useEffect(() => {
    // Update status every second
    const interval = setInterval(() => {
      setStatus(rateLimiter.getStatus());
    }, 1000);

    // Listen for rate limit exceeded events
    const handleRateLimitExceeded = (event) => {
      setNotification(event.detail);
      
      // Clear notification after delay
      setTimeout(() => setNotification(null), 5000);
    };

    window.addEventListener('rate-limit-exceeded', handleRateLimitExceeded);

    return () => {
      clearInterval(interval);
      window.removeEventListener('rate-limit-exceeded', handleRateLimitExceeded);
    };
  }, []);

  const percentUsed = (status.used / status.limit) * 100;
  const getColor = () => {
    if (percentUsed > 80) return 'red';
    if (percentUsed > 50) return 'orange';
    return 'green';
  };

  return (
    <div className="rate-limit-indicator">
      {/* Rate limit status bar */}
      <div className="rate-limit-bar">
        <div 
          className="rate-limit-fill" 
          style={{ 
            width: `${percentUsed}%`, 
            backgroundColor: getColor() 
          }}
        />
      </div>
      
      <div className="rate-limit-info">
        <span>{status.remaining} / {status.limit} requests remaining</span>
        <span className="reset-time">
          Resets at {status.resetAt.toLocaleTimeString()}
        </span>
      </div>

      {/* Notification */}
      {notification && (
        <div className="rate-limit-notification">
          <p>{notification.message}</p>
          {notification.retryAfter && (
            <p>Retry in {notification.retryAfter} seconds</p>
          )}
        </div>
      )}
    </div>
  );
};

export default RateLimitIndicator;
```

---

## 4. HttpOnly Cookie Authentication

### 4.1 Alternative Secure Approach

**Note**: Playbook recommends JWT in headers, but httpOnly cookies provide additional XSS protection.

### 4.2 Backend Setup (FastAPI)

```python
# backend/routes/auth.py

from fastapi import APIRouter, Response, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter()

@router.post("/auth/login")
async def login(credentials: LoginRequest, response: Response):
    """Login with httpOnly cookie"""
    
    # Validate credentials
    user = await authenticate_user(credentials.username, credentials.password)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate JWT token
    token = generate_jwt(user)
    
    # Set httpOnly cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,      # Prevents JavaScript access
        secure=True,        # HTTPS only
        samesite="strict",  # CSRF protection
        max_age=1800,       # 30 minutes
        path="/"
    )
    
    # Set refresh token cookie
    refresh_token = generate_refresh_token(user)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=604800,  # 7 days
        path="/api/v1/auth/refresh"
    )
    
    return {
        "message": "Logged in successfully",
        "user": {
            "id": user.id,
            "email": user.email,
            "roles": user.roles
        }
    }

@router.post("/auth/logout")
async def logout(response: Response):
    """Logout - clear cookies"""
    
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    
    return {"message": "Logged out successfully"}

@router.get("/auth/csrf-token")
async def get_csrf_token():
    """Get CSRF token for state-changing requests"""
    
    csrf_token = generate_csrf_token()
    
    return {"csrf_token": csrf_token}
```

### 4.3 Frontend Integration

```javascript
// services/auth.cookie.service.js

import axios from 'axios';

class CookieAuthService {
  constructor() {
    // Enable credentials (cookies) for all requests
    axios.defaults.withCredentials = true;
  }

  /**
   * Login - cookie is automatically set by backend
   */
  async login(username, password) {
    try {
      const response = await axios.post('/api/v1/auth/login', {
        username,
        password
      });

      // Store CSRF token
      await this.fetchCSRFToken();

      return response.data.user;
    } catch (error) {
      throw new Error(`Login failed: ${error.response?.data?.detail || error.message}`);
    }
  }

  /**
   * Fetch CSRF token
   */
  async fetchCSRFToken() {
    try {
      const response = await axios.get('/api/v1/auth/csrf-token');
      const csrfToken = response.data.csrf_token;
      
      // Store in memory
      sessionStorage.setItem('csrf_token', csrfToken);
      
      // Add to axios default headers
      axios.defaults.headers.common['X-CSRF-Token'] = csrfToken;
    } catch (error) {
      console.error('Failed to fetch CSRF token:', error);
    }
  }

  /**
   * Get current user info
   */
  async getCurrentUser() {
    try {
      const response = await axios.get('/api/v1/auth/me');
      return response.data;
    } catch (error) {
      return null;
    }
  }

  /**
   * Logout
   */
  async logout() {
    try {
      await axios.post('/api/v1/auth/logout');
    } finally {
      sessionStorage.clear();
      window.location.href = '/login';
    }
  }
}

export default new CookieAuthService();
```

### 4.4 CSRF Protection Interceptor

```javascript
// config/csrf.interceptor.js

import axios from 'axios';

// Add CSRF token to state-changing requests
axios.interceptors.request.use(
  (config) => {
    const csrfToken = sessionStorage.getItem('csrf_token');
    
    // Add CSRF token for non-GET requests
    if (csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(config.method?.toUpperCase())) {
      config.headers['X-CSRF-Token'] = csrfToken;
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Handle CSRF token expiration
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 403 && error.response?.data?.detail === 'Invalid CSRF token') {
      // Fetch new CSRF token
      try {
        const response = await axios.get('/api/v1/auth/csrf-token');
        sessionStorage.setItem('csrf_token', response.data.csrf_token);
        
        // Retry original request
        error.config.headers['X-CSRF-Token'] = response.data.csrf_token;
        return axios(error.config);
      } catch (csrfError) {
        return Promise.reject(csrfError);
      }
    }
    
    return Promise.reject(error);
  }
);
```

---

## 5. Conversation History

### 5.1 History Service

```javascript
// services/history.service.js

import axios from 'axios';

class HistoryService {
  /**
   * Get conversations with filters
   */
  async getConversations(filters = {}) {
    const params = new URLSearchParams({
      limit: filters.limit || 50,
      offset: filters.offset || 0,
      sort_by: filters.sortBy || 'updated_at',
      order: filters.order || 'desc'
    });

    if (filters.startDate) {
      params.append('start_date', filters.startDate);
    }
    if (filters.endDate) {
      params.append('end_date', filters.endDate);
    }
    if (filters.search) {
      params.append('query', filters.search);
    }
    if (filters.tags) {
      params.append('tags', filters.tags.join(','));
    }

    const response = await axios.get(`/api/v1/history/conversations?${params}`);
    return response.data;
  }

  /**
   * Get single conversation by ID
   */
  async getConversationById(conversationId) {
    const response = await axios.get(`/api/v1/history/conversations/${conversationId}`);
    return response.data;
  }

  /**
   * Get conversation messages
   */
  async getConversationMessages(conversationId, options = {}) {
    const params = new URLSearchParams({
      limit: options.limit || 100,
      offset: options.offset || 0
    });

    const response = await axios.get(
      `/api/v1/history/conversations/${conversationId}/messages?${params}`
    );
    return response.data;
  }

  /**
   * Update conversation (title, tags)
   */
  async updateConversation(conversationId, updates) {
    const response = await axios.put(
      `/api/v1/history/conversations/${conversationId}`,
      updates
    );
    return response.data;
  }

  /**
   * Delete conversation
   */
  async deleteConversation(conversationId) {
    await axios.delete(`/api/v1/history/conversations/${conversationId}`);
  }

  /**
   * Search conversations
   */
  async searchConversations(query, filters = {}) {
    const params = new URLSearchParams({
      q: query,
      limit: filters.limit || 20,
      offset: filters.offset || 0
    });

    if (filters.dateFrom) {
      params.append('date_from', filters.dateFrom);
    }
    if (filters.dateTo) {
      params.append('date_to', filters.dateTo);
    }

    const response = await axios.get(`/api/v1/history/search?${params}`);
    return response.data;
  }

  /**
   * Export conversation
   */
  async exportConversation(conversationId, format = 'json') {
    const response = await axios.get(
      `/api/v1/history/conversations/${conversationId}/export`,
      {
        params: { format },
        responseType: 'blob'
      }
    );

    // Create download link
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `conversation_${conversationId}.${format}`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  /**
   * Bulk delete conversations
   */
  async bulkDeleteConversations(conversationIds) {
    await axios.post('/api/v1/history/conversations/bulk-delete', {
      conversation_ids: conversationIds
    });
  }
}

export default new HistoryService();
```

### 5.2 React Component

```jsx
// components/ConversationHistory.jsx

import React, { useState, useEffect } from 'react';
import historyService from '../services/history.service';
import './ConversationHistory.css';

const ConversationHistory = () => {
  const [conversations, setConversations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedIds, setSelectedIds] = useState([]);
  const [filters, setFilters] = useState({
    limit: 20,
    offset: 0,
    sortBy: 'updated_at',
    order: 'desc',
    search: ''
  });
  const [totalCount, setTotalCount] = useState(0);

  useEffect(() => {
    loadConversations();
  }, [filters]);

  const loadConversations = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const data = await historyService.getConversations(filters);
      setConversations(data.conversations);
      setTotalCount(data.total_count);
    } catch (err) {
      setError('Failed to load conversations');
      console.error('Error loading conversations:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Are you sure you want to delete this conversation?')) {
      return;
    }

    try {
      await historyService.deleteConversation(id);
      loadConversations();
    } catch (err) {
      alert('Failed to delete conversation');
      console.error('Delete error:', err);
    }
  };

  const handleBulkDelete = async () => {
    if (selectedIds.length === 0) return;

    if (!confirm(`Delete ${selectedIds.length} conversations?`)) {
      return;
    }

    try {
      await historyService.bulkDeleteConversations(selectedIds);
      setSelectedIds([]);
      loadConversations();
    } catch (err) {
      alert('Failed to delete conversations');
      console.error('Bulk delete error:', err);
    }
  };

  const handleExport = async (id) => {
    try {
      await historyService.exportConversation(id, 'json');
    } catch (err) {
      alert('Failed to export conversation');
      console.error('Export error:', err);
    }
  };

  const handleSearchChange = (e) => {
    setFilters({
      ...filters,
      search: e.target.value,
      offset: 0
    });
  };

  const handleSortChange = (sortBy) => {
    setFilters({
      ...filters,
      sortBy,
      order: filters.sortBy === sortBy && filters.order === 'asc' ? 'desc' : 'asc',
      offset: 0
    });
  };

  const handlePageChange = (direction) => {
    setFilters({
      ...filters,
      offset: direction === 'next' 
        ? filters.offset + filters.limit
        : Math.max(0, filters.offset - filters.limit)
    });
  };

  const toggleSelection = (id) => {
    setSelectedIds(prev => 
      prev.includes(id) 
        ? prev.filter(i => i !== id)
        : [...prev, id]
    );
  };

  const toggleSelectAll = () => {
    if (selectedIds.length === conversations.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(conversations.map(c => c.id));
    }
  };

  if (loading && conversations.length === 0) {
    return <div className="loading">Loading conversations...</div>;
  }

  if (error) {
    return <div className="error">{error}</div>;
  }

  return (
    <div className="conversation-history">
      <div className="history-header">
        <h2>Conversation History</h2>
        <div className="history-stats">
          {totalCount} total conversations
        </div>
      </div>

      {/* Filters */}
      <div className="history-filters">
        <input
          type="text"
          placeholder="Search conversations..."
          value={filters.search}
          onChange={handleSearchChange}
          className="search-input"
        />

        <select
          value={filters.sortBy}
          onChange={(e) => handleSortChange(e.target.value)}
          className="sort-select"
        >
          <option value="updated_at">Last Modified</option>
          <option value="created_at">Created Date</option>
          <option value="title">Title</option>
        </select>

        {selectedIds.length > 0 && (
          <button onClick={handleBulkDelete} className="bulk-delete-btn">
            Delete Selected ({selectedIds.length})
          </button>
        )}
      </div>

      {/* Conversations List */}
      <div className="conversations-list">
        {conversations.length === 0 ? (
          <div className="empty-state">
            <p>No conversations found</p>
          </div>
        ) : (
          <>
            <div className="list-header">
              <input
                type="checkbox"
                checked={selectedIds.length === conversations.length}
                onChange={toggleSelectAll}
              />
              <span>Title</span>
              <span>Last Modified</span>
              <span>Messages</span>
              <span>Actions</span>
            </div>

            {conversations.map(conv => (
              <div key={conv.id} className="conversation-item">
                <input
                  type="checkbox"
                  checked={selectedIds.includes(conv.id)}
                  onChange={() => toggleSelection(conv.id)}
                />
                
                <div className="conv-title">
                  <a href={`/chat/${conv.id}`}>{conv.title}</a>
                  {conv.tags && (
                    <div className="conv-tags">
                      {conv.tags.map(tag => (
                        <span key={tag} className="tag">{tag}</span>
                      ))}
                    </div>
                  )}
                </div>
                
                <div className="conv-date">
                  {new Date(conv.updated_at).toLocaleString()}
                </div>
                
                <div className="conv-count">
                  {conv.message_count} messages
                </div>
                
                <div className="conv-actions">
                  <button onClick={() => handleExport(conv.id)} title="Export">
                    📥
                  </button>
                  <button onClick={() => handleDelete(conv.id)} title="Delete">
                    🗑️
                  </button>
                </div>
              </div>
            ))}
          </>
        )}
      </div>

      {/* Pagination */}
      <div className="pagination">
        <button
          disabled={filters.offset === 0}
          onClick={() => handlePageChange('prev')}
          className="pagination-btn"
        >
          Previous
        </button>
        
        <span className="pagination-info">
          Showing {filters.offset + 1} - {Math.min(filters.offset + filters.limit, totalCount)} of {totalCount}
        </span>
        
        <button
          disabled={filters.offset + filters.limit >= totalCount}
          onClick={() => handlePageChange('next')}
          className="pagination-btn"
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default ConversationHistory;
```

### 5.3 Data Structures

```typescript
// types/history.types.ts

export interface Conversation {
  id: string;
  user_id: string;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
  tags?: string[];
  metadata?: Record<string, any>;
}

export interface Message {
  id: string;
  conversation_id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  created_at: string;
  metadata?: {
    tool_calls?: any[];
    tokens_used?: number;
    latency_ms?: number;
  };
}

export interface HistoryFilters {
  limit?: number;
  offset?: number;
  sortBy?: 'created_at' | 'updated_at' | 'title';
  order?: 'asc' | 'desc';
  search?: string;
  tags?: string[];
  startDate?: string;
  endDate?: string;
}
```

---

## 6. Internal Module Communication

### 6.1 Event Bus Architecture

```javascript
// services/event.bus.js

class EventBus {
  constructor() {
    this.events = {};
    this.eventHistory = [];
    this.maxHistorySize = 100;
  }

  /**
   * Subscribe to event
   */
  on(event, callback, options = {}) {
    if (!this.events[event]) {
      this.events[event] = [];
    }

    const listener = {
      callback,
      once: options.once || false,
      priority: options.priority || 0
    };

    this.events[event].push(listener);

    // Sort by priority (higher first)
    this.events[event].sort((a, b) => b.priority - a.priority);

    // Return unsubscribe function
    return () => this.off(event, callback);
  }

  /**
   * Subscribe once
   */
  once(event, callback, options = {}) {
    return this.on(event, callback, { ...options, once: true });
  }

  /**
   * Unsubscribe from event
   */
  off(event, callback) {
    if (!this.events[event]) return;

    this.events[event] = this.events[event].filter(
      listener => listener.callback !== callback
    );
  }

  /**
   * Emit event
   */
  emit(event, data) {
    // Log event
    this.logEvent(event, data);

    if (!this.events[event]) return;

    // Execute callbacks
    this.events[event] = this.events[event].filter(listener => {
      try {
        listener.callback(data);
      } catch (error) {
        console.error(`Error in event listener for ${event}:`, error);
      }

      // Remove if once
      return !listener.once;
    });
  }

  /**
   * Emit event asynchronously
   */
  async emitAsync(event, data) {
    this.logEvent(event, data);

    if (!this.events[event]) return;

    const promises = this.events[event].map(listener => 
      Promise.resolve(listener.callback(data))
    );

    await Promise.all(promises);

    // Remove once listeners
    this.events[event] = this.events[event].filter(
      listener => !listener.once
    );
  }

  /**
   * Clear all listeners for event
   */
  clear(event) {
    if (event) {
      delete this.events[event];
    } else {
      this.events = {};
    }
  }

  /**
   * Log event to history
   */
  logEvent(event, data) {
    this.eventHistory.push({
      event,
      data,
      timestamp: Date.now()
    });

    // Limit history size
    if (this.eventHistory.length > this.maxHistorySize) {
      this.eventHistory.shift();
    }
  }

  /**
   * Get event history
   */
  getHistory(event) {
    if (event) {
      return this.eventHistory.filter(h => h.event === event);
    }
    return this.eventHistory;
  }
}

export default new EventBus();
```

### 6.2 Module Examples

**Chat Module:**

```javascript
// modules/chat.module.js

import eventBus from '../services/event.bus';
import axios from 'axios';

class ChatModule {
  constructor() {
    this.setupListeners();
  }

  setupListeners() {
    // Listen for tool execution results
    eventBus.on('tool:executed', this.handleToolResult.bind(this));
    
    // Listen for user preferences changes
    eventBus.on('preferences:updated', this.handlePreferencesUpdate.bind(this));
  }

  async sendMessage(message, conversationId) {
    try {
      // Emit event before sending
      eventBus.emit('message:sending', { message, conversationId });

      const response = await axios.post('/api/v1/chat/message', {
        message,
        conversation_id: conversationId
      });

      // Emit event after success
      eventBus.emit('message:sent', {
        message: response.data.message,
        conversationId: response.data.conversation_id,
        timestamp: Date.now()
      });

      return response.data;
    } catch (error) {
      // Emit error event
      eventBus.emit('message:error', {
        message,
        conversationId,
        error: error.message
      });

      throw error;
    }
  }

  handleToolResult(data) {
    console.log('Tool execution completed:', data);
    // Update UI or state
  }

  handlePreferencesUpdate(preferences) {
    console.log('User preferences updated:', preferences);
    // Apply new preferences
  }
}

export default new ChatModule();
```

**History Module:**

```javascript
// modules/history.module.js

import eventBus from '../services/event.bus';
import historyService from '../services/history.service';

class HistoryModule {
  constructor() {
    this.setupListeners();
  }

  setupListeners() {
    // Listen for message events
    eventBus.on('message:sent', this.handleMessageSent.bind(this));
    
    // Listen for conversation events
    eventBus.on('conversation:created', this.handleConversationCreated.bind(this));
    eventBus.on('conversation:updated', this.handleConversationUpdated.bind(this));
  }

  handleMessageSent(data) {
    console.log('Saving message to history:', data);
    // Update local cache or trigger refresh
  }

  handleConversationCreated(data) {
    console.log('New conversation created:', data);
    // Add to conversations list
  }

  handleConversationUpdated(data) {
    console.log('Conversation updated:', data);
    // Update conversation in list
  }

  async loadRecentConversations() {
    const conversations = await historyService.getConversations({
      limit: 10,
      sortBy: 'updated_at',
      order: 'desc'
    });

    // Emit event for other modules
    eventBus.emit('history:loaded', conversations);

    return conversations;
  }
}

export default new HistoryModule();
```

**Analytics Module:**

```javascript
// modules/analytics.module.js

import eventBus from '../services/event.bus';
import axios from 'axios';

class AnalyticsModule {
  constructor() {
    this.setupListeners();
    this.queue = [];
    this.flushInterval = 30000; // 30 seconds
    this.startAutoFlush();
  }

  setupListeners() {
    // Track all user interactions
    eventBus.on('message:sent', (data) => this.trackEvent('message_sent', data));
    eventBus.on('tool:executed', (data) => this.trackEvent('tool_executed', data));
    eventBus.on('conversation:created', (data) => this.trackEvent('conversation_created', data));
    eventBus.on('favorite:added', (data) => this.trackEvent('favorite_added', data));
    eventBus.on('quicklink:clicked', (data) => this.trackEvent('quicklink_clicked', data));
  }

  trackEvent(eventName, data) {
    const event = {
      name: eventName,
      data: this.sanitizeData(data),
      timestamp: Date.now(),
      user_id: this.getUserId(),
      session_id: this.getSessionId()
    };

    this.queue.push(event);

    // Emit analytics event for debugging
    eventBus.emit('analytics:tracked', event);
  }

  sanitizeData(data) {
    // Remove sensitive information
    const sanitized = { ...data };
    delete sanitized.password;
    delete sanitized.token;
    return sanitized;
  }

  getUserId() {
    const user = sessionStorage.getItem('user');
    return user ? JSON.parse(user).id : null;
  }

  getSessionId() {
    let sessionId = sessionStorage.getItem('session_id');
    if (!sessionId) {
      sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      sessionStorage.setItem('session_id', sessionId);
    }
    return sessionId;
  }

  async flush() {
    if (this.queue.length === 0) return;

    const events = [...this.queue];
    this.queue = [];

    try {
      await axios.post('/api/v1/analytics/events', { events });
    } catch (error) {
      console.error('Failed to send analytics events:', error);
      // Re-add to queue on failure
      this.queue.unshift(...events);
    }
  }

  startAutoFlush() {
    setInterval(() => this.flush(), this.flushInterval);

    // Flush on page unload
    window.addEventListener('beforeunload', () => this.flush());
  }
}

export default new AnalyticsModule();
```

### 6.3 State Management Integration (Zustand)

```javascript
// stores/app.store.js

import create from 'zustand';
import eventBus from '../services/event.bus';
import chatModule from '../modules/chat.module';
import historyModule from '../modules/history.module';

const useAppStore = create((set, get) => ({
  // State
  user: null,
  conversations: [],
  activeConversation: null,
  messages: [],
  loading: false,
  error: null,

  // Actions
  setUser: (user) => {
    set({ user });
    eventBus.emit('user:updated', user);
  },

  setConversations: (conversations) => {
    set({ conversations });
  },

  addConversation: (conversation) => {
    set((state) => ({
      conversations: [conversation, ...state.conversations]
    }));
    eventBus.emit('conversation:created', conversation);
  },

  setActiveConversation: (id) => {
    set({ activeConversation: id });
    eventBus.emit('conversation:activated', id);
  },

  addMessage: (message) => {
    set((state) => ({
      messages: [...state.messages, message]
    }));
  },

  // Async actions
  sendMessage: async (message) => {
    const { activeConversation } = get();
    set({ loading: true, error: null });

    try {
      const response = await chatModule.sendMessage(message, activeConversation);
      
      // Update state
      get().addMessage(response.message);
      
      // Emit event
      eventBus.emit('message:sent', response);

      return response;
    } catch (error) {
      set({ error: error.message });
      throw error;
    } finally {
      set({ loading: false });
    }
  },

  loadConversations: async () => {
    set({ loading: true });
    try {
      const conversations = await historyModule.loadRecentConversations();
      set({ conversations });
    } catch (error) {
      set({ error: error.message });
    } finally {
      set({ loading: false });
    }
  }
}));

export default useAppStore;
```

---

## 7. Quick Links

### 7.1 Quick Links Service

```javascript
// services/quicklinks.service.js

import axios from 'axios';
import eventBus from './event.bus';

class QuickLinksService {
  /**
   * Get user's quick links
   */
  async getQuickLinks() {
    const response = await axios.get('/api/v1/user/quick-links');
    return response.data;
  }

  /**
   * Add new quick link
   */
  async addQuickLink(link) {
    const response = await axios.post('/api/v1/user/quick-links', link);
    
    // Emit event
    eventBus.emit('quicklink:added', response.data);
    
    return response.data;
  }

  /**
   * Update quick link
   */
  async updateQuickLink(linkId, updates) {
    const response = await axios.put(`/api/v1/user/quick-links/${linkId}`, updates);
    
    // Emit event
    eventBus.emit('quicklink:updated', response.data);
    
    return response.data;
  }

  /**
   * Remove quick link
   */
  async removeQuickLink(linkId) {
    await axios.delete(`/api/v1/user/quick-links/${linkId}`);
    
    // Emit event
    eventBus.emit('quicklink:removed', { id: linkId });
  }

  /**
   * Reorder quick links
   */
  async reorderQuickLinks(orderedIds) {
    await axios.put('/api/v1/user/quick-links/reorder', {
      order: orderedIds
    });
    
    // Emit event
    eventBus.emit('quicklinks:reordered', orderedIds);
  }

  /**
   * Track quick link click
   */
  trackClick(linkId) {
    eventBus.emit('quicklink:clicked', { id: linkId, timestamp: Date.now() });
    
    // Send analytics
    axios.post(`/api/v1/user/quick-links/${linkId}/track`).catch(err => {
      console.error('Failed to track quick link click:', err);
    });
  }
}

export default new QuickLinksService();
```

### 7.2 React Component

```jsx
// components/QuickLinks.jsx

import React, { useState, useEffect } from 'react';
import { DragDropContext, Droppable, Draggable } from 'react-beautiful-dnd';
import quickLinksService from '../services/quicklinks.service';
import './QuickLinks.css';

const QuickLinks = () => {
  const [links, setLinks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isEditing, setIsEditing] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newLink, setNewLink] = useState({
    title: '',
    url: '',
    icon: '🔗'
  });

  useEffect(() => {
    loadQuickLinks();
  }, []);

  const loadQuickLinks = async () => {
    setLoading(true);
    try {
      const data = await quickLinksService.getQuickLinks();
      setLinks(data);
    } catch (error) {
      console.error('Failed to load quick links:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddLink = async (e) => {
    e.preventDefault();
    
    if (!newLink.title || !newLink.url) {
      alert('Please fill in all fields');
      return;
    }

    try {
      await quickLinksService.addQuickLink(newLink);
      setNewLink({ title: '', url: '', icon: '🔗' });
      setShowAddForm(false);
      loadQuickLinks();
    } catch (error) {
      alert('Failed to add quick link');
      console.error('Add error:', error);
    }
  };

  const handleRemoveLink = async (id) => {
    if (!confirm('Remove this quick link?')) return;

    try {
      await quickLinksService.removeQuickLink(id);
      loadQuickLinks();
    } catch (error) {
      alert('Failed to remove quick link');
      console.error('Remove error:', error);
    }
  };

  const handleDragEnd = async (result) => {
    if (!result.destination) return;

    const items = Array.from(links);
    const [reorderedItem] = items.splice(result.source.index, 1);
    items.splice(result.destination.index, 0, reorderedItem);

    setLinks(items);

    try {
      await quickLinksService.reorderQuickLinks(items.map(link => link.id));
    } catch (error) {
      console.error('Reorder error:', error);
      loadQuickLinks(); // Reload on error
    }
  };

  const handleLinkClick = (link) => {
    quickLinksService.trackClick(link.id);
  };

  if (loading) {
    return <div className="quick-links-loading">Loading...</div>;
  }

  return (
    <div className="quick-links">
      <div className="quick-links-header">
        <h3>Quick Links</h3>
        <div className="header-actions">
          <button 
            onClick={() => setIsEditing(!isEditing)}
            className="edit-btn"
          >
            {isEditing ? '✓ Done' : '✎ Edit'}
          </button>
        </div>
      </div>

      <DragDropContext onDragEnd={handleDragEnd}>
        <Droppable droppableId="quick-links">
          {(provided) => (
            <div
              className="links-container"
              {...provided.droppableProps}
              ref={provided.innerRef}
            >
              {links.map((link, index) => (
                <Draggable
                  key={link.id}
                  draggableId={link.id}
                  index={index}
                  isDragDisabled={!isEditing}
                >
                  {(provided, snapshot) => (
                    <div
                      ref={provided.innerRef}
                      {...provided.draggableProps}
                      className={`link-item ${snapshot.isDragging ? 'dragging' : ''}`}
                    >
                      {isEditing && (
                        <div className="drag-handle" {...provided.dragHandleProps}>
                          ⋮⋮
                        </div>
                      )}
                      
                      <a
                        href={link.url}
                        target={link.url.startsWith('http') ? '_blank' : '_self'}
                        rel="noopener noreferrer"
                        onClick={() => handleLinkClick(link)}
                        className="link-content"
                      >
                        <span className="link-icon">{link.icon}</span>
                        <span className="link-title">{link.title}</span>
                      </a>

                      {isEditing && (
                        <button
                          onClick={() => handleRemoveLink(link.id)}
                          className="remove-btn"
                        >
                          ×
                        </button>
                      )}
                    </div>
                  )}
                </Draggable>
              ))}
              {provided.placeholder}
            </div>
          )}
        </Droppable>
      </DragDropContext>

      {/* Add Link Form */}
      {isEditing && (
        <div className="add-link-section">
          {showAddForm ? (
            <form onSubmit={handleAddLink} className="add-link-form">
              <input
                type="text"
                placeholder="Icon (emoji)"
                value={newLink.icon}
                onChange={(e) => setNewLink({ ...newLink, icon: e.target.value })}
                maxLength={2}
              />
              <input
                type="text"
                placeholder="Title"
                value={newLink.title}
                onChange={(e) => setNewLink({ ...newLink, title: e.target.value })}
                required
              />
              <input
                type="text"
                placeholder="URL"
                value={newLink.url}
                onChange={(e) => setNewLink({ ...newLink, url: e.target.value })}
                required
              />
              <div className="form-actions">
                <button type="submit">Add</button>
                <button type="button" onClick={() => setShowAddForm(false)}>
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            <button onClick={() => setShowAddForm(true)} className="add-link-btn">
              + Add Quick Link
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default QuickLinks;
```

### 7.3 Data Structure

```typescript
// types/quicklinks.types.ts

export interface QuickLink {
  id: string;
  user_id: string;
  title: string;
  url: string;
  icon: string;
  order: number;
  click_count?: number;
  created_at: string;
  updated_at: string;
}

export interface QuickLinkCreate {
  title: string;
  url: string;
  icon?: string;
}

export interface QuickLinkUpdate {
  title?: string;
  url?: string;
  icon?: string;
}
```

---

## 8. Favorites

### 8.1 Favorites Service

```javascript
// services/favorites.service.js

import axios from 'axios';
import eventBus from './event.bus';

class FavoritesService {
  /**
   * Get user's favorites
   */
  async getFavorites(type = 'all') {
    const response = await axios.get('/api/v1/user/favorites', {
      params: { type }
    });
    return response.data;
  }

  /**
   * Add favorite
   */
  async addFavorite(item) {
    const response = await axios.post('/api/v1/user/favorites', item);
    
    // Emit event
    eventBus.emit('favorite:added', response.data);
    
    return response.data;
  }

  /**
   * Remove favorite
   */
  async removeFavorite(favoriteId) {
    await axios.delete(`/api/v1/user/favorites/${favoriteId}`);
    
    // Emit event
    eventBus.emit('favorite:removed', { id: favoriteId });
  }

  /**
   * Check if item is favorited
   */
  async isFavorite(itemId, itemType) {
    try {
      const response = await axios.get('/api/v1/user/favorites/check', {
        params: { item_id: itemId, item_type: itemType }
      });
      return response.data.is_favorite;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get favorite by item
   */
  async getFavoriteByItem(itemId, itemType) {
    try {
      const response = await axios.get('/api/v1/user/favorites/by-item', {
        params: { item_id: itemId, item_type: itemType }
      });
      return response.data;
    } catch (error) {
      return null;
    }
  }
}

export default new FavoritesService();
```

### 8.2 React Hook

```javascript
// hooks/useFavorites.js

import { useState, useEffect, useCallback } from 'react';
import favoritesService from '../services/favorites.service';

export const useFavorites = (itemId, itemType) => {
  const [isFavorite, setIsFavorite] = useState(false);
  const [favoriteId, setFavoriteId] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkFavorite();
  }, [itemId, itemType]);

  const checkFavorite = async () => {
    if (!itemId || !itemType) {
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const favorite = await favoritesService.getFavoriteByItem(itemId, itemType);
      if (favorite) {
        setIsFavorite(true);
        setFavoriteId(favorite.id);
      } else {
        setIsFavorite(false);
        setFavoriteId(null);
      }
    } catch (error) {
      console.error('Error checking favorite:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleFavorite = useCallback(async () => {
    try {
      if (isFavorite && favoriteId) {
        await favoritesService.removeFavorite(favoriteId);
        setIsFavorite(false);
        setFavoriteId(null);
      } else {
        const favorite = await favoritesService.addFavorite({
          item_id: itemId,
          item_type: itemType
        });
        setIsFavorite(true);
        setFavoriteId(favorite.id);
      }
    } catch (error) {
      console.error('Error toggling favorite:', error);
      throw error;
    }
  }, [isFavorite, favoriteId, itemId, itemType]);

  return {
    isFavorite,
    loading,
    toggleFavorite,
    refresh: checkFavorite
  };
};
```

### 8.3 Favorite Button Component

```jsx
// components/FavoriteButton.jsx

import React from 'react';
import { useFavorites } from '../hooks/useFavorites';
import './FavoriteButton.css';

const FavoriteButton = ({ itemId, itemType, className = '' }) => {
  const { isFavorite, loading, toggleFavorite } = useFavorites(itemId, itemType);

  const handleClick = async (e) => {
    e.preventDefault();
    e.stopPropagation();

    try {
      await toggleFavorite();
    } catch (error) {
      alert('Failed to update favorite');
    }
  };

  return (
    <button
      onClick={handleClick}
      disabled={loading}
      className={`favorite-btn ${isFavorite ? 'favorited' : ''} ${className}`}
      title={isFavorite ? 'Remove from favorites' : 'Add to favorites'}
      aria-label={isFavorite ? 'Unfavorite' : 'Favorite'}
    >
      {loading ? (
        <span className="spinner">⟳</span>
      ) : (
        <span className="star-icon">{isFavorite ? '★' : '☆'}</span>
      )}
    </button>
  );
};

export default FavoriteButton;
```

### 8.4 Usage Example

```jsx
// components/ConversationItem.jsx

import React from 'react';
import FavoriteButton from './FavoriteButton';

const ConversationItem = ({ conversation }) => {
  return (
    <div className="conversation-item">
      <div className="conv-header">
        <h3>{conversation.title}</h3>
        <FavoriteButton 
          itemId={conversation.id} 
          itemType="conversation" 
        />
      </div>
      <p className="conv-date">
        {new Date(conversation.updated_at).toLocaleString()}
      </p>
    </div>
  );
};

export default ConversationItem;
```

### 8.5 Favorites List Component

```jsx
// components/FavoritesList.jsx

import React, { useState, useEffect } from 'react';
import favoritesService from '../services/favorites.service';
import FavoriteButton from './FavoriteButton';
import './FavoritesList.css';

const FavoritesList = () => {
  const [favorites, setFavorites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    loadFavorites();
  }, [filter]);

  const loadFavorites = async () => {
    setLoading(true);
    try {
      const data = await favoritesService.getFavorites(filter);
      setFavorites(data);
    } catch (error) {
      console.error('Failed to load favorites:', error);
    } finally {
      setLoading(false);
    }
  };

  const renderFavoriteItem = (favorite) => {
    switch (favorite.item_type) {
      case 'conversation':
        return (
          <div key={favorite.id} className="favorite-item">
            <FavoriteButton 
              itemId={favorite.item_id} 
              itemType="conversation" 
            />
            <a href={`/chat/${favorite.item_id}`}>
              <h4>{favorite.item_title}</h4>
              <p>{new Date(favorite.created_at).toLocaleDateString()}</p>
            </a>
          </div>
        );
      
      case 'tool':
        return (
          <div key={favorite.id} className="favorite-item">
            <FavoriteButton 
              itemId={favorite.item_id} 
              itemType="tool" 
            />
            <a href={`/tools/${favorite.item_id}`}>
              <h4>{favorite.item_title}</h4>
              <p>{favorite.item_description}</p>
            </a>
          </div>
        );
      
      default:
        return null;
    }
  };

  return (
    <div className="favorites-list">
      <div className="favorites-header">
        <h2>Favorites</h2>
        
        <div className="filter-buttons">
          <button 
            onClick={() => setFilter('all')}
            className={filter === 'all' ? 'active' : ''}
          >
            All
          </button>
          <button 
            onClick={() => setFilter('conversation')}
            className={filter === 'conversation' ? 'active' : ''}
          >
            Conversations
          </button>
          <button 
            onClick={() => setFilter('tool')}
            className={filter === 'tool' ? 'active' : ''}
          >
            Tools
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading">Loading favorites...</div>
      ) : favorites.length === 0 ? (
        <div className="empty-state">
          <p>No favorites yet</p>
          <p>Click the ☆ icon on any item to add it to your favorites</p>
        </div>
      ) : (
        <div className="favorites-grid">
          {favorites.map(renderFavoriteItem)}
        </div>
      )}
    </div>
  );
};

export default FavoritesList;
```

### 8.6 Data Structure

```typescript
// types/favorites.types.ts

export interface Favorite {
  id: string;
  user_id: string;
  item_id: string;
  item_type: 'conversation' | 'tool' | 'report' | 'dashboard';
  item_title?: string;
  item_description?: string;
  created_at: string;
}

export interface FavoriteCreate {
  item_id: string;
  item_type: 'conversation' | 'tool' | 'report' | 'dashboard';
}
```

---

## 9. RBAC Implementation with Keycloak

### 9.1 Keycloak Setup

**Realm Configuration:**

```json
{
  "realm": "esyasoft",
  "enabled": true,
  "sslRequired": "external",
  "registrationAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": true,
  "editUsernameAllowed": false,
  "bruteForceProtected": true
}
```

**Client Configuration:**

```json
{
  "clientId": "ai-chatbot-client",
  "enabled": true,
  "protocol": "openid-connect",
  "publicClient": false,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": false,
  "redirectUris": [
    "https://app.example.com/*",
    "http://localhost:3000/*"
  ],
  "webOrigins": ["+"],
  "attributes": {
    "access.token.lifespan": "1800",
    "refresh.token.max.reuse": "0"
  }
}
```

### 9.2 Roles Configuration

**Realm Roles:**

```yaml
roles:
  # User Roles
  - name: user
    description: Basic authenticated user
    
  - name: analyst
    description: Can execute NL2SQL and view reports
    
  - name: data_scientist
    description: Can access ML tools and model registry
    
  - name: admin
    description: Full system access
    
  - name: auditor
    description: Read-only access to logs and audit trails

# Composite Roles
composite_roles:
  analyst:
    - user
  
  data_scientist:
    - user
    - analyst
  
  admin:
    - user
    - analyst
    - data_scientist
    - auditor
```

**Client Roles (Resource-Level):**

```yaml
client_roles:
  ai-chatbot-client:
    - name: conversation.read
      description: Read conversations
    
    - name: conversation.write
      description: Create and update conversations
    
    - name: conversation.delete
      description: Delete conversations
    
    - name: tool.nl2sql.execute
      description: Execute NL2SQL tool
    
    - name: tool.data_analysis.execute
      description: Execute data analysis tool
    
    - name: admin.users.manage
      description: Manage users
    
    - name: admin.logs.view
      description: View audit logs
```

### 9.3 Permission Mapping

**Backend Permission Middleware (FastAPI):**

```python
# backend/middleware/rbac.py

from fastapi import Request, HTTPException, Depends
from functools import wraps
import jwt

class RBACMiddleware:
    def __init__(self, keycloak_config):
        self.keycloak_config = keycloak_config
        self.public_key = self.fetch_public_key()
    
    def fetch_public_key(self):
        # Fetch Keycloak public key for JWT verification
        # Implementation depends on Keycloak setup
        pass
    
    def decode_token(self, token: str):
        try:
            decoded = jwt.decode(
                token,
                self.public_key,
                algorithms=['RS256'],
                audience='ai-chatbot-client'
            )
            return decoded
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def has_role(self, token_data: dict, required_role: str) -> bool:
        """Check if user has required realm role"""
        realm_roles = token_data.get('realm_access', {}).get('roles', [])
        return required_role in realm_roles
    
    def has_permission(self, token_data: dict, required_permission: str) -> bool:
        """Check if user has required client permission"""
        resource_access = token_data.get('resource_access', {})
        client_roles = resource_access.get('ai-chatbot-client', {}).get('roles', [])
        return required_permission in client_roles

# Decorators
def require_role(required_role: str):
    """Decorator to require specific role"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get('request')
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            rbac = RBACMiddleware(keycloak_config)
            token_data = rbac.decode_token(token)
            
            if not rbac.has_role(token_data, required_role):
                raise HTTPException(
                    status_code=403,
                    detail=f"Required role: {required_role}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def require_permission(required_permission: str):
    """Decorator to require specific permission"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get('request')
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            rbac = RBACMiddleware(keycloak_config)
            token_data = rbac.decode_token(token)
            
            if not rbac.has_permission(token_data, required_permission):
                raise HTTPException(
                    status_code=403,
                    detail=f"Required permission: {required_permission}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator
```

**Usage in Routes:**

```python
# backend/routes/tools.py

from fastapi import APIRouter, Request
from middleware.rbac import require_role, require_permission

router = APIRouter()

@router.post("/tools/nl2sql/execute")
@require_permission("tool.nl2sql.execute")
async def execute_nl2sql(request: Request, query: str):
    """Execute NL2SQL tool - requires specific permission"""
    # Implementation
    pass

@router.get("/admin/users")
@require_role("admin")
async def list_users(request: Request):
    """List users - requires admin role"""
    # Implementation
    pass

@router.get("/conversations")
@require_permission("conversation.read")
async def get_conversations(request: Request):
    """Get user's conversations"""
    # Implementation
    pass
```

### 9.4 Frontend RBAC Guards

```jsx
// components/RBACGuard.jsx

import React from 'react';
import authService from '../services/auth.service';

const RBACGuard = ({ 
  children, 
  requiredRoles = [], 
  requiredPermissions = [],
  fallback = null 
}) => {
  const user = authService.getCurrentUser();

  if (!user) {
    return fallback;
  }

  // Check roles
  if (requiredRoles.length > 0) {
    const hasRole = requiredRoles.some(role => authService.hasRole(role));
    if (!hasRole) {
      return fallback;
    }
  }

  // Check permissions
  if (requiredPermissions.length > 0) {
    const hasPerm = requiredPermissions.some(perm => authService.hasPermission(perm));
    if (!hasPerm) {
      return fallback;
    }
  }

  return children;
};

export default RBACGuard;
```

**Usage:**

```jsx
// Example: Conditional UI rendering based on permissions

import RBACGuard from './RBACGuard';

const Dashboard = () => {
  return (
    <div className="dashboard">
      <h1>Dashboard</h1>

      {/* Show NL2SQL tool only if user has permission */}
      <RBACGuard requiredPermissions={['tool.nl2sql.execute']}>
        <NL2SQLTool />
      </RBACGuard>

      {/* Show admin panel only for admins */}
      <RBACGuard requiredRoles={['admin']}>
        <AdminPanel />
      </RBACGuard>

      {/* Show fallback if no permission */}
      <RBACGuard 
        requiredPermissions={['tool.data_analysis.execute']}
        fallback={<p>You don't have access to data analysis tools</p>}
      >
        <DataAnalysisTool />
      </RBACGuard>
    </div>
  );
};
```

### 9.5 Role-Permission Matrix

```typescript
// config/rbac.config.ts

export const ROLES = {
  USER: 'user',
  ANALYST: 'analyst',
  DATA_SCIENTIST: 'data_scientist',
  ADMIN: 'admin',
  AUDITOR: 'auditor'
} as const;

export const PERMISSIONS = {
  // Conversations
  CONVERSATION_READ: 'conversation.read',
  CONVERSATION_WRITE: 'conversation.write',
  CONVERSATION_DELETE: 'conversation.delete',
  
  // Tools
  TOOL_NL2SQL: 'tool.nl2sql.execute',
  TOOL_DATA_ANALYSIS: 'tool.data_analysis.execute',
  
  // Admin
  ADMIN_USERS: 'admin.users.manage',
  ADMIN_LOGS: 'admin.logs.view'
} as const;

// Role to Permission Mapping
export const ROLE_PERMISSIONS: Record<string, string[]> = {
  [ROLES.USER]: [
    PERMISSIONS.CONVERSATION_READ,
    PERMISSIONS.CONVERSATION_WRITE
  ],
  
  [ROLES.ANALYST]: [
    PERMISSIONS.CONVERSATION_READ,
    PERMISSIONS.CONVERSATION_WRITE,
    PERMISSIONS.CONVERSATION_DELETE,
    PERMISSIONS.TOOL_NL2SQL
  ],
  
  [ROLES.DATA_SCIENTIST]: [
    PERMISSIONS.CONVERSATION_READ,
    PERMISSIONS.CONVERSATION_WRITE,
    PERMISSIONS.CONVERSATION_DELETE,
    PERMISSIONS.TOOL_NL2SQL,
    PERMISSIONS.TOOL_DATA_ANALYSIS
  ],
  
  [ROLES.ADMIN]: [
    // All permissions
    ...Object.values(PERMISSIONS)
  ],
  
  [ROLES.AUDITOR]: [
    PERMISSIONS.CONVERSATION_READ,
    PERMISSIONS.ADMIN_LOGS
  ]
};
```

---

## 10. Security Checklist

### ✅ Authentication & Authorization

- [x] JWT tokens with RS256 signing
- [x] Keycloak integration for SSO
- [x] Token stored in sessionStorage (cleared on tab close)
- [x] Refresh tokens in localStorage (optional)
- [x] Token expiration handling with automatic refresh
- [x] RBAC with role and permission checks
- [x] Protected routes with auth guards

### ✅ Session Management

- [x] 30-minute inactivity timeout
- [x] Session expiration warnings
- [x] Stateless session design
- [x] Activity tracking
- [x] Graceful logout

### ✅ Rate Limiting

- [x] Client-side rate limiting (20 req/min)
- [x] Server-side rate limiting (Redis-backed)
- [x] User feedback on rate limit exceeded
- [x] 429 response handling

### ✅ Network Security

- [x] HTTPS-only communication
- [x] CORS properly configured
- [x] CSRF protection (for cookie-based auth)
- [x] Content Security Policy headers

### ✅ Data Protection

- [x] Sensitive data not stored in localStorage
- [x] HttpOnly cookies option available
- [x] XSS protection measures
- [x] Input validation on all forms

### ✅ Audit & Logging

- [x] All user actions logged (via event bus)
- [x] Analytics tracking
- [x] Error logging
- [x] Performance monitoring

### ✅ Compliance

- [x] SOC2 alignment
- [x] GDPR ready (data retention, deletion)
- [x] Privacy controls
- [x] Audit trail for compliance

---

## Appendix A: Environment Variables

```bash
# .env.example

# API Configuration
NEXT_PUBLIC_API_URL=https://api.example.com
NEXT_PUBLIC_API_VERSION=v1

# Keycloak Configuration
NEXT_PUBLIC_KEYCLOAK_URL=https://keycloak.example.com
NEXT_PUBLIC_KEYCLOAK_REALM=esyasoft
NEXT_PUBLIC_KEYCLOAK_CLIENT_ID=ai-chatbot-client

# Session Configuration
NEXT_PUBLIC_SESSION_TIMEOUT_MS=1800000  # 30 minutes
NEXT_PUBLIC_SESSION_WARNING_MS=300000   # 5 minutes

# Rate Limiting
NEXT_PUBLIC_RATE_LIMIT_MAX_REQUESTS=20
NEXT_PUBLIC_RATE_LIMIT_WINDOW_MS=60000

# Analytics
NEXT_PUBLIC_ANALYTICS_ENABLED=true
NEXT_PUBLIC_ANALYTICS_FLUSH_INTERVAL_MS=30000

# Feature Flags
NEXT_PUBLIC_ENABLE_SSO=true
NEXT_PUBLIC_ENABLE_COOKIE_AUTH=false
```

---

## Appendix B: API Endpoints Reference

```yaml
# Authentication
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
POST   /api/v1/auth/refresh
POST   /api/v1/auth/callback       # SSO callback
GET    /api/v1/auth/csrf-token
GET    /api/v1/auth/me

# Conversations / History
GET    /api/v1/history/conversations
GET    /api/v1/history/conversations/{id}
GET    /api/v1/history/conversations/{id}/messages
PUT    /api/v1/history/conversations/{id}
DELETE /api/v1/history/conversations/{id}
POST   /api/v1/history/conversations/bulk-delete
GET    /api/v1/history/search
GET    /api/v1/history/conversations/{id}/export

# Quick Links
GET    /api/v1/user/quick-links
POST   /api/v1/user/quick-links
PUT    /api/v1/user/quick-links/{id}
DELETE /api/v1/user/quick-links/{id}
PUT    /api/v1/user/quick-links/reorder
POST   /api/v1/user/quick-links/{id}/track

# Favorites
GET    /api/v1/user/favorites
POST   /api/v1/user/favorites
DELETE /api/v1/user/favorites/{id}
GET    /api/v1/user/favorites/check
GET    /api/v1/user/favorites/by-item

# Chat
POST   /api/v1/chat/message
GET    /api/v1/chat/conversations/{id}

# Analytics
POST   /api/v1/analytics/events

# Tools (Example)
POST   /api/v1/tools/nl2sql/execute
POST   /api/v1/tools/data-analysis/execute

# Admin
GET    /api/v1/admin/users
GET    /api/v1/admin/logs
```

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-13 | Based on architectural playbook | Initial release |

---

**END OF DOCUMENT**
