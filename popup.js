// DOM Elements
const featureToggle = document.getElementById('featureToggle');
const colorPicker = document.getElementById('colorPicker');
const actionBtn = document.getElementById('actionBtn');
const optionsBtn = document.getElementById('optionsBtn');
const resetBtn = document.getElementById('resetBtn');
const pageCount = document.getElementById('pageCount');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  // Load saved settings
  const settings = await chrome.storage.sync.get({
    featureEnabled: true,
    highlightColor: '#3498db',
    pageCount: 0
  });
  
  // Apply settings to UI
  featureToggle.checked = settings.featureEnabled;
  colorPicker.value = settings.highlightColor;
  pageCount.textContent = settings.pageCount;
  
  updateStatus(settings.featureEnabled);
});

// Event Listeners
featureToggle.addEventListener('change', async (e) => {
  const enabled = e.target.checked;
  await chrome.storage.sync.set({ featureEnabled: enabled });
  updateStatus(enabled);
  
  // Send message to content script
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  chrome.tabs.sendMessage(tab.id, {
    action: 'toggleFeature',
    enabled: enabled
  });
});

colorPicker.addEventListener('change', async (e) => {
  await chrome.storage.sync.set({ highlightColor: e.target.value });
  
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  chrome.tabs.sendMessage(tab.id, {
    action: 'updateColor',
    color: e.target.value
  });
});

actionBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // Increment page count
  const settings = await chrome.storage.sync.get(['pageCount']);
  const newCount = (settings.pageCount || 0) + 1;
  await chrome.storage.sync.set({ pageCount: newCount });
  pageCount.textContent = newCount;
  
  // Send action to content script
  chrome.tabs.sendMessage(tab.id, {
    action: 'performAction',
    timestamp: Date.now()
  });
  
  // Show confirmation
  actionBtn.textContent = 'Done!';
  setTimeout(() => {
    actionBtn.textContent = 'Do Something';
  }, 1000);
});

optionsBtn.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

resetBtn.addEventListener('click', async () => {
  await chrome.storage.sync.set({ pageCount: 0 });
  pageCount.textContent = '0';
});

// Helper Functions
function updateStatus(enabled) {
  if (enabled) {
    statusDot.style.background = '#2ecc71';
    statusText.textContent = 'Active';
  } else {
    statusDot.style.background = '#e74c3c';
    statusText.textContent = 'Inactive';
  }
  // Add to popup.js

// Safety scanning functions
async function checkCurrentPageSafety() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  try {
    // Send message to content script to get scan results
    const response = await chrome.tabs.sendMessage(tab.id, { 
      action: 'getSafetyResults' 
    });
    
    if (response && response.results) {
      updateSafetyDisplay(response.results);
    } else {
      document.getElementById('safetyStatus').innerHTML = `
        <p>No scan data available</p>
        <p>Click "Scan This Page" to start</p>
      `;
    }
  } catch (error) {
    document.getElementById('safetyStatus').innerHTML = `
      <p>Cannot scan this page</p>
      <p style="font-size: 12px; color: #888;">${error.message}</p>
    `;
  }
}

function updateSafetyDisplay(results) {
  const safetyDiv = document.getElementById('safetyStatus');
  
  let safetyHTML = `
    <div style="text-align: center; padding: 10px; background: ${results.safetyColor}20; border-radius: 8px; margin-bottom: 10px;">
      <div style="font-size: 32px; font-weight: bold; color: ${results.safetyColor};">${results.safetyScore}/100</div>
      <div style="color: ${results.safetyColor}; font-weight: bold;">${results.safetyLevel}</div>
    </div>
  `;
  
  if (results.warnings.length > 0) {
    safetyHTML += `
      <div style="margin-bottom: 10px;">
        <div style="color: #e74c3c; font-size: 14px; margin-bottom: 5px;">
          ⚠️ ${results.warnings.length} warning${results.warnings.length > 1 ? 's' : ''}
        </div>
    `;
    
    // Show top 2 warnings
    results.warnings.slice(0, 2).forEach(warning => {
      safetyHTML += `
        <div style="font-size: 12px; color: #666; margin-bottom: 3px;">
          • ${warning.message.substring(0, 50)}${warning.message.length > 50 ? '...' : ''}
        </div>
      `;
    });
    
    safetyHTML += `</div>`;
  }
  
  safetyDiv.innerHTML = safetyHTML;
}

// Add event listeners for scan buttons
document.getElementById('scanNowBtn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // Send scan command to content script
  chrome.tabs.sendMessage(tab.id, { action: 'rescanPage' });
  
  // Update status
  document.getElementById('safetyStatus').innerHTML = `
    <p>Scanning page...</p>
    <div class="spinner"></div>
  `;
  
  // Wait and refresh
  setTimeout(() => {
    checkCurrentPageSafety();
  }, 2000);
});

document.getElementById('viewReportBtn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // Ask content script to show full report
  chrome.tabs.sendMessage(tab.id, { action: 'showSafetyReport' });
  
  // Close popup
  window.close();
});

// Add to DOMContentLoaded event
document.addEventListener('DOMContentLoaded', async () => {
  // ... existing code ...
  
  // Check current page safety
  await checkCurrentPageSafety();
});

// Add spinner CSS to popup.css
const spinnerCSS = `
.spinner {
  border: 3px solid #f3f3f3;
  border-top: 3px solid #3498db;
  border-radius: 50%;
  width: 20px;
  height: 20px;
  animation: spin 1s linear infinite;
  margin: 10px auto;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
`;

// Add this CSS to popup.css
}