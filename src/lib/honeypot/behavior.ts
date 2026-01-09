/**
 * Trap - Behavior Analysis Module
 * 
 * Tracks mouse movements, typing patterns, and other behavioral signals
 * to distinguish bots from humans and collect forensic data.
 */

// ============================================
// Types
// ============================================

export interface MouseData {
  movements: MouseMovement[];
  clicks: MouseClick[];
  scrolls: ScrollEvent[];
  totalDistance: number;
  averageSpeed: number;
  straightLineRatio: number; // Bots often move in straight lines
  pauseCount: number;
  isBot: boolean;
  botConfidence: number;
}

export interface MouseMovement {
  x: number;
  y: number;
  timestamp: number;
  speed?: number;
  angle?: number;
}

export interface MouseClick {
  x: number;
  y: number;
  timestamp: number;
  button: number;
  target: string;
}

export interface ScrollEvent {
  scrollY: number;
  timestamp: number;
  delta: number;
}

export interface TypingData {
  keystrokes: Keystroke[];
  averageInterval: number;
  intervalVariance: number;
  mistakeCount: number;
  backspaceCount: number;
  pasteCount: number;
  wordsPerMinute: number;
  isBot: boolean;
  botConfidence: number;
}

export interface Keystroke {
  key: string;
  timestamp: number;
  duration: number; // Key hold time
  interval: number; // Time since last key
}

export interface BehaviorAnalysis {
  mouse: MouseData;
  typing: TypingData;
  sessionDuration: number;
  pageVisibility: PageVisibility[];
  focusChanges: FocusChange[];
  isBot: boolean;
  botConfidence: number;
  riskScore: number;
}

export interface PageVisibility {
  state: 'visible' | 'hidden';
  timestamp: number;
}

export interface FocusChange {
  type: 'focus' | 'blur';
  timestamp: number;
}

// ============================================
// Client-side tracking script
// ============================================

export function getBehaviorTrackingScript(endpoint: string): string {
  return `
<script>
(function() {
  const behavior = {
    mouse: {
      movements: [],
      clicks: [],
      scrolls: [],
      lastPos: null,
      totalDistance: 0,
    },
    typing: {
      keystrokes: [],
      lastKeyTime: null,
      lastKeyDown: {},
    },
    visibility: [],
    focus: [],
    startTime: Date.now(),
  };

  // Mouse movement tracking
  let moveThrottle = null;
  document.addEventListener('mousemove', (e) => {
    if (moveThrottle) return;
    moveThrottle = setTimeout(() => { moveThrottle = null; }, 50);
    
    const now = Date.now();
    const pos = { x: e.clientX, y: e.clientY, timestamp: now };
    
    if (behavior.mouse.lastPos) {
      const dx = pos.x - behavior.mouse.lastPos.x;
      const dy = pos.y - behavior.mouse.lastPos.y;
      const distance = Math.sqrt(dx * dx + dy * dy);
      const dt = now - behavior.mouse.lastPos.timestamp;
      pos.speed = dt > 0 ? distance / dt : 0;
      pos.angle = Math.atan2(dy, dx);
      behavior.mouse.totalDistance += distance;
    }
    
    behavior.mouse.movements.push(pos);
    behavior.mouse.lastPos = pos;
    
    // Keep only last 500 movements
    if (behavior.mouse.movements.length > 500) {
      behavior.mouse.movements.shift();
    }
  });

  // Click tracking
  document.addEventListener('click', (e) => {
    behavior.mouse.clicks.push({
      x: e.clientX,
      y: e.clientY,
      timestamp: Date.now(),
      button: e.button,
      target: e.target.tagName + (e.target.id ? '#' + e.target.id : '') + (e.target.className ? '.' + e.target.className.split(' ')[0] : ''),
    });
  });

  // Scroll tracking
  let scrollThrottle = null;
  document.addEventListener('scroll', () => {
    if (scrollThrottle) return;
    scrollThrottle = setTimeout(() => { scrollThrottle = null; }, 100);
    
    const lastScroll = behavior.mouse.scrolls[behavior.mouse.scrolls.length - 1];
    behavior.mouse.scrolls.push({
      scrollY: window.scrollY,
      timestamp: Date.now(),
      delta: lastScroll ? window.scrollY - lastScroll.scrollY : 0,
    });
    
    if (behavior.mouse.scrolls.length > 100) {
      behavior.mouse.scrolls.shift();
    }
  });

  // Keydown tracking (for timing)
  document.addEventListener('keydown', (e) => {
    const now = Date.now();
    behavior.typing.lastKeyDown[e.key] = now;
  });

  // Keyup tracking (for duration and intervals)
  document.addEventListener('keyup', (e) => {
    const now = Date.now();
    const downTime = behavior.typing.lastKeyDown[e.key] || now;
    const duration = now - downTime;
    const interval = behavior.typing.lastKeyTime ? now - behavior.typing.lastKeyTime : 0;
    
    behavior.typing.keystrokes.push({
      key: e.key.length === 1 ? '*' : e.key, // Mask actual keys for privacy
      timestamp: now,
      duration: duration,
      interval: interval,
    });
    
    behavior.typing.lastKeyTime = now;
    
    if (behavior.typing.keystrokes.length > 200) {
      behavior.typing.keystrokes.shift();
    }
  });

  // Paste detection
  document.addEventListener('paste', () => {
    behavior.typing.keystrokes.push({
      key: 'PASTE',
      timestamp: Date.now(),
      duration: 0,
      interval: 0,
    });
  });

  // Page visibility
  document.addEventListener('visibilitychange', () => {
    behavior.visibility.push({
      state: document.visibilityState,
      timestamp: Date.now(),
    });
  });

  // Focus/blur
  window.addEventListener('focus', () => {
    behavior.focus.push({ type: 'focus', timestamp: Date.now() });
  });
  window.addEventListener('blur', () => {
    behavior.focus.push({ type: 'blur', timestamp: Date.now() });
  });

  // Analyze and send data
  function analyzeBehavior() {
    const analysis = {
      mouse: {
        movementCount: behavior.mouse.movements.length,
        clickCount: behavior.mouse.clicks.length,
        scrollCount: behavior.mouse.scrolls.length,
        totalDistance: behavior.mouse.totalDistance,
        movements: behavior.mouse.movements.slice(-50), // Last 50
        clicks: behavior.mouse.clicks.slice(-20),
        scrolls: behavior.mouse.scrolls.slice(-20),
      },
      typing: {
        keystrokeCount: behavior.typing.keystrokes.length,
        keystrokes: behavior.typing.keystrokes.slice(-50),
        pasteCount: behavior.typing.keystrokes.filter(k => k.key === 'PASTE').length,
        backspaceCount: behavior.typing.keystrokes.filter(k => k.key === 'Backspace').length,
      },
      visibility: behavior.visibility,
      focus: behavior.focus,
      sessionDuration: Date.now() - behavior.startTime,
      timestamp: new Date().toISOString(),
    };

    // Calculate bot indicators
    analysis.botIndicators = {
      // Bots often have very consistent mouse speeds
      mouseSpeedVariance: calculateVariance(behavior.mouse.movements.map(m => m.speed || 0)),
      // Bots often move in straight lines
      straightLineRatio: calculateStraightLineRatio(behavior.mouse.movements),
      // Bots often have very consistent typing intervals
      typingIntervalVariance: calculateVariance(behavior.typing.keystrokes.map(k => k.interval)),
      // Bots rarely use backspace
      backspaceRatio: behavior.typing.keystrokes.length > 0 
        ? analysis.typing.backspaceCount / behavior.typing.keystrokes.length 
        : 0,
      // Bots often paste instead of type
      pasteRatio: behavior.typing.keystrokes.length > 0 
        ? analysis.typing.pasteCount / behavior.typing.keystrokes.length 
        : 0,
    };

    return analysis;
  }

  function calculateVariance(arr) {
    if (arr.length < 2) return 0;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    return arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
  }

  function calculateStraightLineRatio(movements) {
    if (movements.length < 3) return 0;
    let straightCount = 0;
    for (let i = 2; i < movements.length; i++) {
      const angle1 = movements[i-1].angle || 0;
      const angle2 = movements[i].angle || 0;
      if (Math.abs(angle1 - angle2) < 0.1) straightCount++;
    }
    return straightCount / (movements.length - 2);
  }

  // Send data periodically and on form submit
  function sendBehaviorData() {
    const data = analyzeBehavior();
    fetch('${endpoint}', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }).catch(() => {});
  }

  // Send every 10 seconds
  setInterval(sendBehaviorData, 10000);

  // Send on form submit
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', sendBehaviorData);
  });

  // Send before leaving
  window.addEventListener('beforeunload', sendBehaviorData);
})();
</script>`;
}

// ============================================
// Server-side analysis
// ============================================

export function analyzeBehaviorData(data: any): BehaviorAnalysis {
  const mouseIsBot = analyzeMouseForBot(data.mouse, data.botIndicators);
  const typingIsBot = analyzeTypingForBot(data.typing, data.botIndicators);
  
  const overallBotConfidence = (mouseIsBot.confidence + typingIsBot.confidence) / 2;
  const isBot = overallBotConfidence > 0.7;
  
  // Calculate risk score (0-100)
  let riskScore = 0;
  if (isBot) riskScore += 40;
  if (data.botIndicators?.straightLineRatio > 0.8) riskScore += 20;
  if (data.botIndicators?.typingIntervalVariance < 10) riskScore += 20;
  if (data.typing?.pasteCount > 2) riskScore += 10;
  if (data.sessionDuration < 3000) riskScore += 10; // Less than 3 seconds
  
  return {
    mouse: {
      movements: data.mouse?.movements || [],
      clicks: data.mouse?.clicks || [],
      scrolls: data.mouse?.scrolls || [],
      totalDistance: data.mouse?.totalDistance || 0,
      averageSpeed: calculateAverageSpeed(data.mouse?.movements),
      straightLineRatio: data.botIndicators?.straightLineRatio || 0,
      pauseCount: countPauses(data.mouse?.movements),
      isBot: mouseIsBot.isBot,
      botConfidence: mouseIsBot.confidence,
    },
    typing: {
      keystrokes: data.typing?.keystrokes || [],
      averageInterval: calculateAverageInterval(data.typing?.keystrokes),
      intervalVariance: data.botIndicators?.typingIntervalVariance || 0,
      mistakeCount: 0, // Would need more data
      backspaceCount: data.typing?.backspaceCount || 0,
      pasteCount: data.typing?.pasteCount || 0,
      wordsPerMinute: calculateWPM(data.typing?.keystrokes, data.sessionDuration),
      isBot: typingIsBot.isBot,
      botConfidence: typingIsBot.confidence,
    },
    sessionDuration: data.sessionDuration || 0,
    pageVisibility: data.visibility || [],
    focusChanges: data.focus || [],
    isBot,
    botConfidence: overallBotConfidence,
    riskScore: Math.min(100, riskScore),
  };
}

function analyzeMouseForBot(mouse: any, indicators: any): { isBot: boolean; confidence: number } {
  let botScore = 0;
  
  // No mouse movement at all
  if (!mouse?.movementCount || mouse.movementCount < 5) {
    botScore += 0.3;
  }
  
  // Very straight movements
  if (indicators?.straightLineRatio > 0.8) {
    botScore += 0.4;
  } else if (indicators?.straightLineRatio > 0.6) {
    botScore += 0.2;
  }
  
  // Very low speed variance (robotic)
  if (indicators?.mouseSpeedVariance < 0.1) {
    botScore += 0.3;
  }
  
  return {
    isBot: botScore > 0.5,
    confidence: Math.min(1, botScore),
  };
}

function analyzeTypingForBot(typing: any, indicators: any): { isBot: boolean; confidence: number } {
  let botScore = 0;
  
  // Very consistent typing (robotic)
  if (indicators?.typingIntervalVariance < 10) {
    botScore += 0.4;
  }
  
  // No backspaces (bots don't make mistakes)
  if (typing?.keystrokeCount > 20 && typing?.backspaceCount === 0) {
    botScore += 0.3;
  }
  
  // High paste ratio
  if (indicators?.pasteRatio > 0.5) {
    botScore += 0.3;
  }
  
  return {
    isBot: botScore > 0.5,
    confidence: Math.min(1, botScore),
  };
}

function calculateAverageSpeed(movements: MouseMovement[]): number {
  if (!movements || movements.length < 2) return 0;
  const speeds = movements.filter(m => m.speed !== undefined).map(m => m.speed!);
  return speeds.length > 0 ? speeds.reduce((a, b) => a + b, 0) / speeds.length : 0;
}

function countPauses(movements: MouseMovement[]): number {
  if (!movements || movements.length < 2) return 0;
  let pauses = 0;
  for (let i = 1; i < movements.length; i++) {
    const dt = movements[i].timestamp - movements[i-1].timestamp;
    if (dt > 500) pauses++; // Pause > 500ms
  }
  return pauses;
}

function calculateAverageInterval(keystrokes: Keystroke[]): number {
  if (!keystrokes || keystrokes.length < 2) return 0;
  const intervals = keystrokes.filter(k => k.interval > 0).map(k => k.interval);
  return intervals.length > 0 ? intervals.reduce((a, b) => a + b, 0) / intervals.length : 0;
}

function calculateWPM(keystrokes: Keystroke[], sessionDuration: number): number {
  if (!keystrokes || keystrokes.length < 5 || !sessionDuration) return 0;
  const charCount = keystrokes.filter(k => k.key === '*').length;
  const minutes = sessionDuration / 60000;
  const words = charCount / 5; // Average word length
  return minutes > 0 ? Math.round(words / minutes) : 0;
}

export default {
  getBehaviorTrackingScript,
  analyzeBehaviorData,
};

