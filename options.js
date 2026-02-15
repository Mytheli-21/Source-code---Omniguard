document.addEventListener('DOMContentLoaded', loadSettings);

async function loadSettings() {
  const settings = await chrome.storage.sync.get({
    enableNotifications: true,
    autoStart: false,
    theme: 'light',
    fontSize: 14,
    apiKey: '',
    logLevel: 'info'
  });
  
  document.getElementById('enableNotifications').checked = settings.enableNotifications;
  document.getElementById('autoStart').checked = settings.autoStart;
  document.getElementById('theme').value = settings.theme;
  document.getElementById('fontSize').value = settings.fontSize;
  document.getElementById('fontSizeValue').textContent = settings.fontSize + 'px';
  document.getElementById('apiKey').value = settings.apiKey;
  document.getElementById('logLevel').value = settings.logLevel;
}

// Update font size display
document.getElementById('fontSize').addEventListener('input', (e) => {
  document.getElementById('fontSizeValue').textContent = e.target.value + 'px';
});

// Save settings
document.getElementById('saveSettings').addEventListener('click', async () => {
  const settings = {
    enableNotifications: document.getElementById('enableNotifications').checked,
    autoStart: document.getElementById('autoStart').checked,
    theme: document.getElementById('theme').value,
    fontSize: parseInt(document.getElementById('fontSize').value),
    apiKey: document.getElementById('apiKey').value,
    logLevel: document.getElementById('logLevel').value
  };
  
  await chrome.storage.sync.set(settings);
  showStatus('Settings saved successfully!', 'success');
});

// Data management
document.getElementById('exportData').addEventListener('click', async () => {
  const data = await chrome.storage.sync.get(null);
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = 'extension-settings.json';
  a.click();
  
  URL.revokeObjectURL(url);
  showStatus('Settings exported!', 'success');
});

document.getElementById('importData').addEventListener('click', () => {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'application/json';
  
  input.onchange = async (e) => {
    const file = e.target.files[0];
    const text = await file.text();
    const data = JSON.parse(text);
    
    await chrome.storage.sync.set(data);
    loadSettings();
    showStatus('Settings imported successfully!', 'success');
  };
  
  input.click();
});

document.getElementById('resetData').addEventListener('click', async () => {
  if (confirm('Are you sure you want to reset all settings? This cannot be undone.')) {
    await chrome.storage.sync.clear();
    loadSettings();
    showStatus('All settings have been reset.', 'success');
  }
});

function showStatus(message, type) {
  const status = document.getElementById('statusMessage');
  status.textContent = message;
  status.className = `status ${type}`;
  status.style.display = 'block';
  
  setTimeout(() => {
    status.style.display = 'none';
  }, 3000);
}