let ws;
let chart;
let wsConnected = false;
const wsUrl = "ws://127.0.0.1:8000/ws/chat";

/* 🧠 Risk Logic */
function assessRisk(score) {
    if (score < 40) return { risk: "High Risk", className: "high" };
    if (score < 70) return { risk: "Moderate Risk", className: "medium" };
    return { risk: "Safe", className: "safe" };
}

/* 🎤 Voice */
function startVoice() {
  let recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
  recognition.lang = "en-US";

  recognition.onresult = function(event) {
    document.getElementById("text").value = event.results[0][0].transcript;
  };

  recognition.start();
}

/* 📊 Chart */
function showChart(score) {
  let ctx = document.getElementById('chart');

  if (chart) chart.destroy();

  chart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Trust Score'],
      datasets: [{
        label: 'Score',
        data: [score]
      }]
    }
  });
}

/* 🔌 WebSocket */
function connectWebSocket() {
  try {
    ws = new WebSocket(wsUrl);
  } catch (error) {
    updateStatus("⚠️ WebSocket init failed");
    return;
  }

  ws.onopen = () => {
    wsConnected = true;
    updateStatus("✅ Connected via WebSocket");
  };

  ws.onmessage = (event) => {
    let data = JSON.parse(event.data);
    let reasonsText = data.reasons ? "\nReasons: " + data.reasons.join(", ") : "";

    addMessage(
      "bot",
      `Score: ${data.trust_score}\nRisk: ${data.risk}\n${data.alert}${reasonsText}`
    );

    showChart(data.trust_score);
  };

  ws.onclose = () => {
    wsConnected = false;
    updateStatus("❌ Disconnected... retrying in 3s");
    setTimeout(connectWebSocket, 3000);
  };

  ws.onerror = () => {
    wsConnected = false;
    updateStatus("⚠️ WebSocket error");
  };
}

function updateStatus(msg) {
  document.getElementById("status").innerText = msg;
}

async function sendHttp(text) {
  try {
    const res = await fetch("http://127.0.0.1:8000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    let reasonsText = data.reasons ? "\nReasons: " + data.reasons.join(", ") : "";

    addMessage(
      "bot",
      `Score: ${data.trust_score}\nRisk: ${data.risk}\n${data.alert}${reasonsText}`
    );
    showChart(data.trust_score);
    updateStatus("✅ Analysis returned via HTTP fallback");
  } catch (error) {
    updateStatus("❌ HTTP fallback failed. Start the backend server.");
  }
}

/* 💬 Chat */
function addMessage(sender, text, extraClass = "") {
  let chat = document.getElementById("chat");

  let div = document.createElement("div");
  div.className = `message ${sender} ${extraClass}`;
  div.innerText = text;

  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

/* 🚀 Send */
function sendMessage() {
  let input = document.getElementById("text");
  let text = input.value.trim();
  if (!text) return;

  addMessage("user", text);

  if (wsConnected && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ text }));
    updateStatus("✅ Sent via WebSocket");
  } else {
    updateStatus("⚠️ WebSocket unavailable. Sending via HTTP...");
    sendHttp(text);
  }

  input.value = "";
}

function handleKeyPress(e) {
  if (e.key === "Enter") sendMessage();
}

// Start
connectWebSocket();