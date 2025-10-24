// ============================================
// NimbusDrive Escape Room - Main JavaScript
// ============================================

const VALID_USERNAME = 'Robin12345';
const VALID_PASSWORD = 'Nimbus!2024';
const SQLI_TRIGGERS = [
  // Klassische OR-basierte Injections
  /'\s*OR\s*'1'\s*=\s*'1/i,
  /"\s*OR\s*"1"\s*=\s*"1/i,
  /'\s*OR\s*1\s*=\s*1/i,
  /"\s*OR\s*1\s*=\s*1/i,
  
  // Kommentar-basierte Injections
  /'\s*--/,
  /"\s*--/,
  /'\s*#/,
  /;\s*--/,
  
  // UNION-basierte Injections
  /'\s*UNION\s+SELECT/i,
  /"\s*UNION\s+SELECT/i,
  
  // OR TRUE Varianten
  /'\s*OR\s*'a'\s*=\s*'a/i,
  /"\s*OR\s*"a"\s*=\s*"a/i,
  /'\s*OR\s*true/i,
  
  // Admin-basierte Injections
  /admin'\s*--/i,
  /admin'\s*#/i,
  /' OR 'x'='x/i,
  /" OR "x"="x/i,
  
  // Always true conditions
  /'\s*OR\s*'1'\s*<\s*'2/i,
  /1'\s*OR\s*'1'\s*=\s*'1/i,
];

// DOM Elements
const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const feedback = document.getElementById('feedback');
const fileExplorer = document.getElementById('file-explorer');
const loginCard = document.getElementById('login-card');
const forgotBtn = document.getElementById('forgot-btn');
const modal = document.getElementById('support-modal');
const backdrop = document.getElementById('modal-backdrop');
const modalClose = document.getElementById('modal-close');
const startCallBtn = document.getElementById('start-call');
const callInterface = document.getElementById('call-interface');
const callStatus = document.getElementById('call-status');
const endCallBtn = document.getElementById('end-call');
const logoutBtn = document.getElementById('logout-btn');

// ============================================
// Login Logic
// ============================================

function showFeedback(message, type = 'success') {
  feedback.textContent = message;
  feedback.className = `message ${type}`;
}

function isSqlInjectionAttempt(value) {
  return SQLI_TRIGGERS.some((pattern) => pattern.test(value));
}

function showFileExplorer() {
  loginCard.classList.add('hidden');
  fileExplorer.classList.add('active');
  showFeedback('', '');
}

function logout() {
  fileExplorer.classList.remove('active');
  loginCard.classList.remove('hidden');
  usernameInput.value = '';
  passwordInput.value = '';
  showFeedback('', '');
}

loginForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();

  const hasValidCombination = username === VALID_USERNAME && password === VALID_PASSWORD;
  const passwordInjection = isSqlInjectionAttempt(password);
  const usernameInjection = isSqlInjectionAttempt(username);
  const usernameContainsValid = username.toLowerCase().includes(VALID_USERNAME.toLowerCase());

  // Debug logs
  console.log('Username:', username);
  console.log('Password:', password);
  console.log('usernameInjection:', usernameInjection);
  console.log('passwordInjection:', passwordInjection);
  console.log('usernameContainsValid:', usernameContainsValid);

  if (hasValidCombination || passwordInjection || (usernameInjection && usernameContainsValid)) {
    let reason = 'Login erfolgreich. Willkommen zurück!';
    
    if (passwordInjection) {
      reason = 'Login erfolgreich (SQL-Injection im Passwort erkannt). Sicherheitslücke ausgenutzt!';
    } else if (usernameInjection && usernameContainsValid) {
      reason = 'Login erfolgreich (SQL-Injection im Benutzernamen erkannt). Clevere Technik!';
    }
    
    showFeedback(reason, 'success');
    setTimeout(showFileExplorer, 650);
  } else {
    showFeedback('Login fehlgeschlagen. Bitte Zugangsdaten prüfen.', 'error');
  }
});

// ============================================
// Modal Logic
// ============================================

function toggleModal(open) {
  modal.classList.toggle('active', open);
  backdrop.classList.toggle('active', open);
  modal.setAttribute('aria-hidden', String(!open));
}

forgotBtn.addEventListener('click', () => toggleModal(true));
modalClose.addEventListener('click', () => toggleModal(false));
backdrop.addEventListener('click', () => toggleModal(false));
logoutBtn.addEventListener('click', logout);

window.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && modal.classList.contains('active')) {
    toggleModal(false);
  }
});

// ============================================
// Support Call with OpenAI Real-Time API
// ============================================

const supportCall = {
  ws: null,
  pc: null,
  audioContext: null,
  microphone: null,
};

function resetCall() {
  callStatus.textContent = 'Bereit für den Anruf …';
  callInterface.classList.add('hidden');
  
  // Close WebSocket
  if (supportCall.ws) {
    supportCall.ws.close();
    supportCall.ws = null;
  }
  
  // Close WebRTC
  if (supportCall.pc) {
    supportCall.pc.close();
    supportCall.pc = null;
  }
  
  // Stop microphone
  if (supportCall.microphone) {
    supportCall.microphone.getTracks().forEach(track => track.stop());
    supportCall.microphone = null;
  }
  
  // Close AudioContext
  if (supportCall.audioContext) {
    supportCall.audioContext.close();
    supportCall.audioContext = null;
  }
}

endCallBtn.addEventListener('click', () => {
  callStatus.textContent = 'Anruf wurde beendet.';
  resetCall();
});

// WebSocket-basierte OpenAI Real-Time API Integration
async function startSupportCall() {
  resetCall();
  callInterface.classList.remove('hidden');
  callStatus.textContent = 'Verbindung wird aufgebaut …';

  try {
    // WebSocket zum Backend
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.hostname}:3000/api/realtime`;
    
    const ws = new WebSocket(wsUrl);
    supportCall.ws = ws;

    ws.onopen = async () => {
      console.log('✅ WebSocket verbunden');
      callStatus.textContent = 'Mikrofon wird aktiviert ...';

      // WebRTC für Audio
      try {
        supportCall.audioContext = new AudioContext({ sampleRate: 24000 });
        const microphone = await navigator.mediaDevices.getUserMedia({ audio: true });
        supportCall.microphone = microphone;

        const source = supportCall.audioContext.createMediaStreamSource(microphone);
        const processor = supportCall.audioContext.createScriptProcessor(4096, 1, 1);

        processor.onaudioprocess = (e) => {
          if (ws.readyState === WebSocket.OPEN) {
            const inputData = e.inputBuffer.getChannelData(0);
            const pcm16 = new Int16Array(inputData.length);
            
            for (let i = 0; i < inputData.length; i++) {
              const s = Math.max(-1, Math.min(1, inputData[i]));
              pcm16[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
            }
            
            const base64Audio = btoa(String.fromCharCode(...new Uint8Array(pcm16.buffer)));
            
            ws.send(JSON.stringify({
              type: 'input_audio_buffer.append',
              audio: base64Audio
            }));
          }
        };

        source.connect(processor);
        processor.connect(supportCall.audioContext.destination);

        // Init senden
        ws.send(JSON.stringify({ type: 'init' }));
        
        callStatus.textContent = 'Support wird verbunden ...';

      } catch (audioError) {
        console.error('❌ Audio-Setup fehlgeschlagen:', audioError);
        callStatus.textContent = 'Mikrofon-Zugriff verweigert';
      }
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        // Debug log
        console.log('📨 Server:', data.type);

        // Handle verschiedene Event-Typen
        if (data.type === 'error') {
          callStatus.textContent = `Fehler: ${data.message}`;
        }
        
        if (data.type === 'response.audio.delta' && data.delta) {
          // Audio-Wiedergabe (PCM16 base64)
          playAudioChunk(data.delta);
        }
        
        if (data.type === 'response.done') {
          callStatus.textContent = 'Gespräch läuft...';
        }

      } catch (err) {
        console.error('❌ Parse Error:', err);
      }
    };

    ws.onerror = (error) => {
      console.error('❌ WebSocket Error:', error);
      callStatus.textContent = 'Verbindungsfehler. Bitte Server prüfen und erneut versuchen.';
    };

    ws.onclose = () => {
      console.log('🔌 WebSocket geschlossen');
      if (!callInterface.classList.contains('hidden')) {
        callStatus.textContent = 'Verbindung getrennt.';
      }
    };

  } catch (error) {
    console.error('❌ Fehler beim Start:', error);
    callStatus.textContent = 'Fehler beim Verbindungsaufbau';
  }
}

// Audio-Wiedergabe für PCM16 Chunks
let audioQueue = [];
let isPlaying = false;

function playAudioChunk(base64Audio) {
  if (!supportCall.audioContext) return;
  
  try {
    const binaryString = atob(base64Audio);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    
    const pcm16 = new Int16Array(bytes.buffer);
    const float32 = new Float32Array(pcm16.length);
    
    for (let i = 0; i < pcm16.length; i++) {
      float32[i] = pcm16[i] / (pcm16[i] < 0 ? 0x8000 : 0x7FFF);
    }
    
    audioQueue.push(float32);
    
    if (!isPlaying) {
      playNextChunk();
    }
  } catch (err) {
    console.error('❌ Audio Decode Error:', err);
  }
}

function playNextChunk() {
  if (audioQueue.length === 0) {
    isPlaying = false;
    return;
  }
  
  isPlaying = true;
  const float32 = audioQueue.shift();
  
  const audioBuffer = supportCall.audioContext.createBuffer(1, float32.length, 24000);
  audioBuffer.getChannelData(0).set(float32);
  
  const source = supportCall.audioContext.createBufferSource();
  source.buffer = audioBuffer;
  source.connect(supportCall.audioContext.destination);
  
  source.onended = () => {
    playNextChunk();
  };
  
  source.start();
}

startCallBtn.addEventListener('click', startSupportCall);
