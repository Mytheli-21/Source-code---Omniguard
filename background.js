// OmniProtect Background Service Worker - Manifest V3
'use strict';

console.log('🔒 OmniProtect: Background service worker initialized');

// ====================
// INITIALIZATION
// ====================

// Initialize on install
chrome.runtime.onInstalled.addListener((details) => {
  console.log(`🔒 OmniProtect: Extension ${details.reason}`);
  
  // Set default settings
  const defaultSettings = {
    // Core protection settings
    protectionEnabled: true,
    autoScan: true,
    realTimeProtection: true,
    
    // Security levels
    securityLevel: 'balanced', // 'minimal', 'balanced', 'maximum'
    blockMalicious: true,
    blockPhishing: true,
    blockTrackers: false,
    blockAds: false,
    
    // Privacy settings
    vpnEnabled: false,
    hideIpAddress: false,
    clearCookiesOnExit: false,
    
    // Notification settings
    showNotifications: true,
    soundOnThreat: true,
    desktopNotifications: true,
    
    // UI settings
    theme: 'light',
    showSafetyScore: true,
    floatingButton: true,
    
    // Data settings
    autoReportThreats: false,
    collectAnonymousData: false,
    
    // System
    version: '1.0.0',
    installedDate: new Date().toISOString(),
    lastUpdated: new Date().toISOString()
  };
  
  chrome.storage.sync.set(defaultSettings, () => {
    console.log('🔒 OmniProtect: Default settings saved');
    
    // Initialize threat database
    initializeThreatDatabase();
    
    // Show welcome notification
    if (details.reason === 'install') {
      showWelcomeNotification();
    }
  });
});

// Initialize threat database
function initializeThreatDatabase() {
  const initialThreats = {
    knownPhishingSites: [
      'example-phishing-site.com',
      'fake-login-page.net'
    ],
    knownMalwareDomains: [
      'malware-distribution.org',
      'crypto-miner-proxy.biz'
    ],
    suspiciousPatterns: [
      'login-verify-account',
      'secure-update-credentials',
      'bank-confirmation'
    ],
    safeDomains: [
      'google.com',
      'github.com',
      'wikipedia.org',
      'microsoft.com',
      'apple.com'
    ]
  };
  
  chrome.storage.local.set({ threatDatabase: initialThreats }, () => {
    console.log('🔒 OmniProtect: Threat database initialized');
  });
}

// ====================
// MESSAGE HANDLING
// ====================

// Handle all extension messages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log(`🔒 OmniProtect: Message received - ${request.action || request.type}`);
  
  // Handle different message types
  switch (request.action || request.type) {
    
    // ===== DIAGNOSTICS & STATUS =====
    case 'ping':
      handlePing(request, sender, sendResponse);
      break;
      
    case 'diagnostics':
      handleDiagnostics(request, sender, sendResponse);
      return true; // Keep channel open for async
      
    case 'getStatus':
      handleGetStatus(request, sender, sendResponse);
      return true;
      
    // ===== SCANNING & SECURITY =====
    case 'scanComplete':
      handleScanComplete(request, sender, sendResponse);
      return true;
      
    case 'scanPage':
      handleScanPage(request, sender, sendResponse);
      return true;
      
    case 'checkUrlSafety':
      handleCheckUrlSafety(request, sender, sendResponse);
      return true;
      
    case 'reportSite':
      handleReportSite(request, sender, sendResponse);
      return true;
      
    // ===== SETTINGS MANAGEMENT =====
    case 'updateSettings':
      handleUpdateSettings(request, sender, sendResponse);
      return true;
      
    case 'getSettings':
      handleGetSettings(request, sender, sendResponse);
      return true;
      
    case 'resetSettings':
      handleResetSettings(request, sender, sendResponse);
      return true;
      
    // ===== LOGGING & ANALYTICS =====
    case 'logEvent':
      handleLogEvent(request, sender, sendResponse);
      return true;
      
    // ===== DEFAULT =====
    default:
      sendResponse({
        error: 'Unknown action',
        received: request,
        availableActions: [
          'ping', 'diagnostics', 'getStatus',
          'scanPage', 'checkUrlSafety', 'reportSite',
          'updateSettings', 'getSettings', 'resetSettings',
          'logEvent'
        ]
      });
  }
  
  return false; // Synchronous response handled
});

// ====================
// MESSAGE HANDLERS
// ====================

function handlePing(request, sender, sendResponse) {
  sendResponse({
    status: 'active',
    timestamp: Date.now(),
    version: '1.0.0',
    service: 'OmniProtect'
  });
}

function handleDiagnostics(request, sender, sendResponse) {
  chrome.storage.sync.get(null, (settings) => {
    chrome.storage.local.get(['threatDatabase', 'securityLogs'], (localData) => {
      const diagnostics = {
        serviceWorker: 'active',
        timestamp: Date.now(),
        settings: settings,
        threatCount: localData.threatDatabase ? 
          Object.values(localData.threatDatabase).flat().length : 0,
        logCount: localData.securityLogs ? localData.securityLogs.length : 0,
        chromeVersion: navigator.userAgent.match(/Chrome\/(\d+)/)?.[1] || 'unknown',
        manifestVersion: chrome.runtime.getManifest().manifest_version
      };
      sendResponse(diagnostics);
    });
  });
}

function handleGetStatus(request, sender, sendResponse) {
  chrome.storage.sync.get(['protectionEnabled', 'securityLevel', 'autoScan'], (settings) => {
    chrome.storage.local.get(['scansToday', 'threatsBlocked', 'lastScan'], (stats) => {
      sendResponse({
        protection: settings.protectionEnabled ? 'active' : 'inactive',
        level: settings.securityLevel,
        autoScan: settings.autoScan,
        stats: {
          scansToday: stats.scansToday || 0,
          threatsBlocked: stats.threatsBlocked || 0,
          lastScan: stats.lastScan || 'Never'
        },
        currentTab: sender.tab?.url || 'unknown'
      });
    });
  });
}

function handleScanComplete(request, sender, sendResponse) {
  console.log(`🔒 OmniProtect: Scan complete for ${request.url}`);
  
  // Update scan statistics
  const today = new Date().toDateString();
  chrome.storage.local.get(['scansToday', 'lastScan'], (data) => {
    let scansToday = data.scansToday || 0;
    
    // Reset if new day
    if (!data.lastScan || !data.lastScan.includes(today)) {
      scansToday = 1;
    } else {
      scansToday += 1;
    }
    
    chrome.storage.local.set({
      scansToday: scansToday,
      lastScan: new Date().toISOString()
    }, () => {
      // Log the scan
      logSecurityEvent({
        type: 'scan_complete',
        url: request.url,
        results: request.results,
        timestamp: Date.now()
      });
      
      // Check if we need to show notification
      if (request.results && !request.results.isSafe) {
        showThreatNotification(request.url, request.results);
      }
      
      sendResponse({ 
        logged: true, 
        statsUpdated: true,
        scansToday: scansToday
      });
    });
  });
}

function handleScanPage(request, sender, sendResponse) {
  if (!sender.tab?.id) {
    sendResponse({ error: 'No tab specified' });
    return;
  }
  
  // Send scan command to content script
  chrome.tabs.sendMessage(sender.tab.id, {
    action: 'performScan',
    requestId: request.requestId || Date.now()
  }, (response) => {
    if (chrome.runtime.lastError) {
      sendResponse({ error: 'Content script not ready', details: chrome.runtime.lastError.message });
    } else {
      sendResponse({ 
        scanning: true, 
        tabId: sender.tab.id,
        url: sender.tab.url
      });
    }
  });
}

function handleCheckUrlSafety(request, sender, sendResponse) {
  const url = request.url || sender.tab?.url;
  if (!url) {
    sendResponse({ error: 'No URL provided' });
    return;
  }
  
  chrome.storage.local.get(['threatDatabase'], (data) => {
    const safetyCheck = checkUrlAgainstThreats(url, data.threatDatabase);
    sendResponse({
      url: url,
      isSafe: safetyCheck.isSafe,
      threats: safetyCheck.threats,
      confidence: safetyCheck.confidence,
      recommendation: safetyCheck.recommendation
    });
  });
}

function handleReportSite(request, sender, sendResponse) {
  console.log(`🔒 OmniProtect: Site reported - ${request.url}`);
  
  // Log the report
  logSecurityEvent({
    type: 'site_reported',
    url: request.url,
    reason: request.reason || 'User reported',
    results: request.results,
    timestamp: Date.now()
  });
  
  // Add to reported sites
  chrome.storage.local.get(['reportedSites'], (data) => {
    let reportedSites = data.reportedSites || [];
    reportedSites.push({
      url: request.url,
      timestamp: Date.now(),
      reason: request.reason,
      userReported: true
    });
    
    // Keep only last 1000 reports
    if (reportedSites.length > 1000) {
      reportedSites = reportedSites.slice(-1000);
    }
    
    chrome.storage.local.set({ reportedSites: reportedSites }, () => {
      // Show confirmation
      if (request.showNotification !== false) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '✅ Site Reported',
          message: 'Thank you for helping improve OmniProtect security!',
          priority: 1
        });
      }
      
      sendResponse({ 
        reported: true, 
        message: 'Site reported successfully',
        reportId: Date.now()
      });
    });
  });
}

function handleUpdateSettings(request, sender, sendResponse) {
  if (!request.settings || typeof request.settings !== 'object') {
    sendResponse({ error: 'Invalid settings object' });
    return;
  }
  
  chrome.storage.sync.set(request.settings, () => {
    // Log settings change
    logSecurityEvent({
      type: 'settings_updated',
      changes: Object.keys(request.settings),
      timestamp: Date.now()
    });
    
    sendResponse({ 
      success: true, 
      message: 'Settings updated successfully',
      updated: Object.keys(request.settings)
    });
  });
}

function handleGetSettings(request, sender, sendResponse) {
  chrome.storage.sync.get(null, (settings) => {
    sendResponse(settings);
  });
}

function handleResetSettings(request, sender, sendResponse) {
  const defaultSettings = {
    protectionEnabled: true,
    securityLevel: 'balanced',
    autoScan: true,
    showNotifications: true
  };
  
  chrome.storage.sync.set(defaultSettings, () => {
    sendResponse({ 
      success: true, 
      message: 'Settings reset to defaults',
      settings: defaultSettings
    });
  });
}

function handleLogEvent(request, sender, sendResponse) {
  logSecurityEvent(request.event);
  sendResponse({ logged: true, eventType: request.event?.type });
}

// ====================
// SECURITY FUNCTIONS
// ====================

function checkUrlAgainstThreats(url, threatDatabase) {
  if (!url || !threatDatabase) {
    return { isSafe: true, threats: [], confidence: 'low', recommendation: 'scan' };
  }
  
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (error) {
    return { isSafe: false, threats: [{type: 'invalid_url', message: 'Invalid URL format'}], confidence: 'high', recommendation: 'avoid' };
  }
  
  const hostname = parsedUrl.hostname;
  let threats = [];
  let isSafe = true;
  let confidence = 'high';
  
  // Check against known phishing sites
  if (threatDatabase.knownPhishingSites) {
    threatDatabase.knownPhishingSites.forEach(site => {
      if (hostname.includes(site) || hostname.endsWith(`.${site}`)) {
        threats.push({ type: 'phishing', source: 'known_database', match: site });
        isSafe = false;
        confidence = 'very-high';
      }
    });
  }
  
  // Check against known malware domains
  if (threatDatabase.knownMalwareDomains) {
    threatDatabase.knownMalwareDomains.forEach(domain => {
      if (hostname.includes(domain)) {
        threats.push({ type: 'malware', source: 'known_database', match: domain });
        isSafe = false;
        confidence = 'very-high';
      }
    });
  }
  
  // Check safe domains (whitelist)
  if (threatDatabase.safeDomains && isSafe) {
    if (threatDatabase.safeDomains.some(safeDomain => hostname.endsWith(safeDomain))) {
      isSafe = true;
      confidence = 'high';
    }
  }
  
  // Generate recommendation
  let recommendation = isSafe ? 'safe_to_browse' : 'avoid_page';
  if (threats.length > 0 && !isSafe) {
    recommendation = 'immediate_block';
  } else if (threats.length > 0) {
    recommendation = 'caution_advised';
  }
  
  return { isSafe, threats, confidence, recommendation };
}

// ====================
// LOGGING FUNCTIONS
// ====================

function logSecurityEvent(event) {
  chrome.storage.local.get(['securityLogs'], (data) => {
    let securityLogs = data.securityLogs || [];
    
    securityLogs.push({
      ...event,
      id: Date.now() + Math.random().toString(36).substr(2, 9),
      extensionVersion: '1.0.0'
    });
    
    // Keep only last 1000 logs
    if (securityLogs.length > 1000) {
      securityLogs = securityLogs.slice(-1000);
    }
    
    chrome.storage.local.set({ securityLogs: securityLogs });
  });
}

// ====================
// NOTIFICATION FUNCTIONS
// ====================

function showThreatNotification(url, results) {
  chrome.storage.sync.get(['showNotifications', 'desktopNotifications'], (settings) => {
    
    if (!settings.showNotifications || !settings.desktopNotifications) {
      return;
    }
    
    const hostname = new URL(url).hostname;
    const threatCount = results.warnings?.length || 0;
    
    if (threatCount > 0) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '⚠️ OmniProtect Security Alert',
        message: `${threatCount} threat${threatCount !== 1 ? 's' : ''} detected on ${hostname}`,
        priority: 2
      });
    }
  });
}

function showWelcomeNotification() {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '🎉 Welcome to OmniProtect!',
    message: 'Your browsing is now protected. Click the extension icon to configure settings.',
    priority: 1
  });
}

// ====================
// TAB MONITORING
// ====================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only proceed when page is fully loaded
  if (changeInfo.status !== 'complete' || !tab.url) return;
  
  // Skip internal Chrome pages
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
    return;
  }
  
  console.log(`🔒 OmniProtect: Monitoring tab update - ${tab.url}`);
  
  chrome.storage.sync.get(['protectionEnabled', 'autoScan'], (settings) => {
    
    if (settings.protectionEnabled && settings.autoScan) {
      // Quick URL check against threat database
      chrome.storage.local.get(['threatDatabase'], (data) => {
        const safetyCheck = checkUrlAgainstThreats(tab.url, data.threatDatabase);
        
        if (!safetyCheck.isSafe) {
          console.log(`🔒 OmniProtect: Unsafe URL detected - ${tab.url}`);
          // We'll handle blocking in the content script
        }
        
        // Send scan request to content script
        setTimeout(() => {
          chrome.tabs.sendMessage(tabId, {
            action: 'autoScan',
            url: tab.url,
            timestamp: Date.now()
          }, (response) => {
            if (chrome.runtime.lastError) {
              // Content script might not be ready yet - normal
            }
          });
        }, 1000);
      });
    }
  });
});

// ====================
// SERVICE WORKER MAINTENANCE
// ====================

// Keep service worker alive with periodic activity
function serviceWorkerHeartbeat() {
  chrome.storage.local.set({ 
    lastHeartbeat: Date.now(),
    serviceWorkerStatus: 'active'
  });
  
  // Periodic cleanup
  cleanupOldData();
}

// Clean up old data
function cleanupOldData() {
  chrome.storage.local.get(['securityLogs'], (data) => {
    if (data.securityLogs) {
      const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
      const recentLogs = data.securityLogs.filter(log => log.timestamp > oneWeekAgo);
      
      if (recentLogs.length !== data.securityLogs.length) {
        chrome.storage.local.set({ securityLogs: recentLogs });
        console.log(`🔒 OmniProtect: Cleaned up ${data.securityLogs.length - recentLogs.length} old logs`);
      }
    }
  });
}

// ====================
// INITIALIZATION
// ====================

// Handle extension startup
chrome.runtime.onStartup.addListener(() => {
  console.log('🔒 OmniProtect: Browser started');
  serviceWorkerHeartbeat();
});

// Initialize periodic heartbeat
serviceWorkerHeartbeat();
setInterval(serviceWorkerHeartbeat, 30000); // Every 30 seconds

// Log startup complete
console.log('🔒 OmniProtect: Background service worker setup complete');