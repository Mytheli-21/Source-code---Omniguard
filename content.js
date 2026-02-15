// OmniProtect Content Script - Website Security Scanner
'use strict';

console.log('🔒 OmniProtect: Content script loaded on', window.location.href);

// ====================
// GLOBAL VARIABLES
// ====================

let websiteScanner = null;
let safetyIndicator = null;
let currentScanResults = null;
const DEBUG = true;

// ====================
// DEBUG UTILITIES
// ====================

function debugLog(...args) {
  if (DEBUG) {
    console.log('🔍 OmniProtect:', ...args);
  }
}

// ====================
// WEBSITE SCANNER CLASS
// ====================

class WebsiteScanner {
  constructor() {
    this.results = {
      safetyScore: 100,
      safetyLevel: 'Unknown',
      safetyColor: '#95a5a6',
      warnings: [],
      recommendations: [],
      isSafe: true,
      scanTime: Date.now(),
      url: window.location.href
    };
  }

  // Main scan function
  async scan() {
    debugLog('Starting security scan...');
    
    try {
      // Reset results
      this.results = {
        safetyScore: 100,
        safetyLevel: 'Unknown',
        safetyColor: '#95a5a6',
        warnings: [],
        recommendations: [],
        isSafe: true,
        scanTime: Date.now(),
        url: window.location.href,
        domain: window.location.hostname
      };

      // Run all security checks
      await this.checkHTTPS();
      await this.checkSSL();
      await this.checkSuspiciousElements();
      await this.checkPhishingIndicators();
      await this.checkMalwareSigns();
      await this.checkMixedContent();
      await this.checkPrivacyIssues();
      await this.checkCookies();
      await this.checkSocialEngineering();

      // Calculate final score
      this.calculateScore();
      
      // Log results
      debugLog('Scan complete:', this.results);
      
      // Send results to background
      this.sendResultsToBackground();
      
      // Update safety indicator
      this.updateSafetyIndicator();
      
      return this.results;
      
    } catch (error) {
      console.error('🔒 OmniProtect: Scan error:', error);
      return this.results;
    }
  }

  // ====================
  // SECURITY CHECKS
  // ====================

  async checkHTTPS() {
    const isHTTPS = window.location.protocol === 'https:';
    
    if (!isHTTPS) {
      this.addWarning({
        type: 'security',
        message: 'Website is not using HTTPS (insecure connection)',
        severity: 'high',
        fix: 'Use HTTPS for secure communication'
      });
      this.results.safetyScore -= 30;
    } else {
      this.addRecommendation({
        type: 'security',
        message: 'Website uses HTTPS (secure connection)',
        icon: '✅'
      });
    }
  }

  async checkSSL() {
    if (window.location.protocol === 'https:') {
      const hasSSLIssue = this.detectSSLIssues();
      if (hasSSLIssue) {
        this.addWarning({
          type: 'ssl',
          message: 'Potential SSL certificate issues detected',
          severity: 'high',
          fix: 'Fix mixed content or SSL configuration'
        });
        this.results.safetyScore -= 20;
      } else {
        this.addRecommendation({
          type: 'security',
          message: 'Valid SSL certificate detected',
          icon: '✅'
        });
      }
    }
  }

  detectSSLIssues() {
    // Check for mixed content (already handled separately)
    // Additional SSL checks can be added here
    return false;
  }

  async checkSuspiciousElements() {
    // Check for hidden iframes
    const suspiciousIframes = Array.from(document.querySelectorAll('iframe'))
      .filter(iframe => {
        const src = iframe.src || '';
        const style = window.getComputedStyle(iframe);
        return src.includes('ad') || 
               src.includes('track') || 
               src.includes('click') ||
               style.display === 'none' ||
               style.visibility === 'hidden' ||
               iframe.width === '0' ||
               iframe.height === '0';
      });
    
    if (suspiciousIframes.length > 0) {
      this.addWarning({
        type: 'privacy',
        message: `${suspiciousIframes.length} hidden or tracking iframes detected`,
        severity: 'medium',
        fix: 'Review and remove unnecessary iframes'
      });
      this.results.safetyScore -= 10;
    }

    // Check for excessive hidden elements
    const hiddenElements = document.querySelectorAll('*[style*="display: none"], *[style*="visibility: hidden"]');
    if (hiddenElements.length > 100) {
      this.addWarning({
        type: 'suspicious',
        message: `Unusually high number of hidden elements (${hiddenElements.length})`,
        severity: 'low',
        fix: 'Review page structure for suspicious content'
      });
      this.results.safetyScore -= 5;
    }

    // Check for obfuscated scripts
    const scripts = document.querySelectorAll('script');
    const obfuscatedScripts = Array.from(scripts).filter(script => {
      const content = script.textContent || '';
      return content.includes('eval(') ||
             content.includes('document.write(') ||
             content.includes('fromCharCode') ||
             content.includes('unescape(') ||
             content.length > 10000 && content.match(/[a-zA-Z]{50,}/); // Long encoded strings
    });
    
    if (obfuscatedScripts.length > 0) {
      this.addWarning({
        type: 'suspicious',
        message: `${obfuscatedScripts.length} potentially obfuscated scripts found`,
        severity: 'medium',
        fix: 'Review scripts for malicious content'
      });
      this.results.safetyScore -= 15;
    }
  }

  async checkPhishingIndicators() {
    const url = window.location.href.toLowerCase();
    const hostname = window.location.hostname.toLowerCase();
    
    // Common phishing indicators
    const phishingKeywords = [
      'login', 'signin', 'account', 'verify', 'security',
      'bank', 'paypal', 'ebay', 'amazon', 'facebook', 'google',
      'update', 'confirm', 'password', 'credential', 'wallet',
      'crypto', 'bitcoin', 'authentication'
    ];
    
    // Check for URL obfuscation
    if (url.includes('@') || url.includes('//@')) {
      this.addWarning({
        type: 'phishing',
        message: 'URL contains obfuscation techniques (@ symbol)',
        severity: 'high',
        fix: 'Avoid URLs with @ symbols in the path'
      });
      this.results.safetyScore -= 25;
    }
    
    // Check for IP address instead of domain
    const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    if (ipPattern.test(hostname)) {
      this.addWarning({
        type: 'phishing',
        message: 'Website uses IP address instead of domain name',
        severity: 'medium',
        fix: 'Legitimate sites usually use domain names'
      });
      this.results.safetyScore -= 15;
    }
    
    // Check for look-alike domains
    const lookAlikePatterns = [
      /g00gle/, /faceb00k/, /paypai/, /arnazon/, /ebray/,
      /micr0soft/, /app1e/, /netfl1x/, /tw1tter/, /1nstagram/
    ];
    
    lookAlikePatterns.forEach(pattern => {
      if (pattern.test(hostname)) {
        this.addWarning({
          type: 'phishing',
          message: 'Domain appears to mimic a popular website',
          severity: 'critical',
          fix: 'Verify the domain name carefully'
        });
        this.results.safetyScore -= 40;
      }
    });
    
    // Check for excessive subdomains
    const subdomainCount = hostname.split('.').length - 2; // Subtract TLD and domain
    if (subdomainCount > 3) {
      phishingKeywords.forEach(keyword => {
        if (hostname.includes(keyword)) {
          this.addWarning({
            type: 'phishing',
            message: `Sensitive keyword "${keyword}" with multiple subdomains`,
            severity: 'medium',
            fix: 'Be cautious with complex subdomain structures'
          });
          this.results.safetyScore -= 15;
        }
      });
    }
    
    // Check page content for phishing indicators
    const pageText = document.body.innerText.toLowerCase();
    const phishingTextIndicators = [
      'urgent action required',
      'verify your account',
      'suspicious activity detected',
      'click here to secure',
      'password expired',
      'account suspended'
    ];
    
    phishingTextIndicators.forEach(indicator => {
      if (pageText.includes(indicator)) {
        this.addWarning({
          type: 'phishing',
          message: `Page contains phishing language: "${indicator}"`,
          severity: 'medium',
          fix: 'Be cautious of urgent security messages'
        });
        this.results.safetyScore -= 10;
      }
    });
  }

  async checkMalwareSigns() {
    // Check for cryptocurrency miners
    const minerPatterns = [
      /coin-hive\.com/i,
      /cryptoloot\.pro/i,
      /miner\.pr0gramm/i,
      /webmine\.cz/i,
      /minemaster\.club/i,
      /coinhive\.com/i,
      /jsecoin\.com/i,
      /minero\.cc/i,
      /crypto-loot\.com/i
    ];
    
    // Check scripts
    const scripts = document.querySelectorAll('script');
    let minerFound = false;
    
    scripts.forEach(script => {
      const src = script.src || '';
      const content = script.textContent || '';
      
      minerPatterns.forEach(pattern => {
        if (pattern.test(src) || pattern.test(content)) {
          minerFound = true;
          this.addWarning({
            type: 'malware',
            message: 'Cryptocurrency mining script detected',
            severity: 'critical',
            fix: 'Block cryptocurrency mining scripts'
          });
          this.results.safetyScore -= 50;
        }
      });
    });
    
    // Check for malicious iframe injections
    const iframes = document.querySelectorAll('iframe');
    const maliciousIframes = Array.from(iframes).filter(iframe => {
      const src = iframe.src || '';
      return src.includes('exploit') ||
             src.includes('malware') ||
             src.includes('virus') ||
             src.includes('trojan') ||
             src.includes('payload');
    });
    
    if (maliciousIframes.length > 0) {
      this.addWarning({
        type: 'malware',
        message: `${maliciousIframes.length} potentially malicious iframes detected`,
        severity: 'critical',
        fix: 'Remove or block malicious iframes'
      });
      this.results.safetyScore -= 40;
    }
    
    // Check for drive-by download links
    const downloadLinks = Array.from(document.querySelectorAll('a'))
      .filter(link => {
        const href = link.href || '';
        const text = link.textContent || '';
        return (href.endsWith('.exe') || href.endsWith('.bat') || href.endsWith('.cmd')) &&
               !text.toLowerCase().includes('download') &&
               !text.toLowerCase().includes('install');
      });
    
    if (downloadLinks.length > 0) {
      this.addWarning({
        type: 'malware',
        message: `${downloadLinks.length} suspicious download links detected`,
        severity: 'high',
        fix: 'Avoid unexpected executable downloads'
      });
      this.results.safetyScore -= 30;
    }
  }

  async checkMixedContent() {
    if (window.location.protocol === 'https:') {
      const insecureElements = document.querySelectorAll(`
        script[src^="http://"],
        img[src^="http://"],
        iframe[src^="http://"],
        link[href^="http://"][rel="stylesheet"],
        audio[src^="http://"],
        video[src^="http://"],
        source[src^="http://"],
        embed[src^="http://"],
        object[data^="http://"]
      `);
      
      if (insecureElements.length > 0) {
        this.addWarning({
          type: 'security',
          message: `${insecureElements.length} insecure (HTTP) resources loaded on HTTPS page`,
          severity: 'medium',
          fix: 'Load all resources over HTTPS'
        });
        this.results.safetyScore -= 15;
      }
    }
  }

  async checkPrivacyIssues() {
    // Check for excessive tracking
    const trackers = document.querySelectorAll(`
      script[src*="google-analytics"],
      script[src*="googletagmanager"],
      script[src*="facebook.net"],
      script[src*="doubleclick"],
      script[src*="scorecardresearch"],
      script[src*="hotjar"],
      img[src*="track"],
      img[src*="pixel"],
      iframe[src*="ad"]
    `);
    
    if (trackers.length > 5) {
      this.addWarning({
        type: 'privacy',
        message: `Excessive tracking detected (${trackers.length} trackers)`,
        severity: 'medium',
        fix: 'Use privacy tools to block trackers'
      });
      this.results.safetyScore -= 10;
    }
    
    // Check for fingerprinting scripts
    const fingerprintingPatterns = [
      'fingerprint',
      'canvas',
      'webgl',
      'fonts',
      'plugins',
      'timezone',
      'screen',
      'localStorage',
      'sessionStorage',
      'indexedDB'
    ];
    
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      const content = script.textContent.toLowerCase();
      fingerprintingPatterns.forEach(pattern => {
        if (content.includes(pattern) && content.length > 500) {
          this.addWarning({
            type: 'privacy',
            message: 'Potential browser fingerprinting detected',
            severity: 'medium',
            fix: 'Use anti-fingerprinting browser extensions'
          });
          this.results.safetyScore -= 15;
        }
      });
    });
  }

  async checkCookies() {
    // Check for cookie consent (GDPR compliance)
    const cookieElements = document.querySelectorAll(`
      *[class*="cookie"],
      *[id*="cookie"],
      *[class*="gdpr"],
      *[id*="gdpr"],
      *[class*="consent"],
      *[id*="consent"],
      button:contains("accept"),
      button:contains("agree"),
      button:contains("ok")
    `);
    
    if (cookieElements.length > 0) {
      this.addRecommendation({
        type: 'privacy',
        message: 'Cookie consent banner detected (may indicate GDPR compliance)',
        icon: '✅'
      });
    }
    
    // Check for excessive cookies
    try {
      const cookies = document.cookie.split(';').length;
      if (cookies > 20) {
        this.addWarning({
          type: 'privacy',
          message: `Excessive number of cookies (${cookies})`,
          severity: 'low',
          fix: 'Regularly clear cookies for this site'
        });
        this.results.safetyScore -= 5;
      }
    } catch (error) {
      // Cookie access might be blocked
    }
  }

  async checkSocialEngineering() {
    // Check for fake urgency
    const urgentElements = document.querySelectorAll(`
      *:contains("URGENT"),
      *:contains("IMMEDIATE"),
      *:contains("ACT NOW"),
      *:contains("LAST CHANCE"),
      *:contains("LIMITED TIME"),
      *:contains("EXCLUSIVE OFFER")
    `);
    
    if (urgentElements.length > 3) {
      this.addWarning({
        type: 'social-engineering',
        message: 'Page uses urgency/scarcity tactics',
        severity: 'low',
        fix: 'Be cautious of urgent demands'
      });
      this.results.safetyScore -= 5;
    }
    
    // Check for fake security warnings
    const fakeSecurityElements = document.querySelectorAll(`
      *:contains("Your computer is infected"),
      *:contains("Virus detected"),
      *:contains("System alert"),
      *:contains("Security warning"),
      *:contains("Critical update")
    `);
    
    if (fakeSecurityElements.length > 0) {
      this.addWarning({
        type: 'social-engineering',
        message: 'Fake security warnings detected',
        severity: 'high',
        fix: 'Ignore fake security alerts'
      });
      this.results.safetyScore -= 20;
    }
  }

  // ====================
  // HELPER METHODS
  // ====================

  addWarning(warning) {
    this.results.warnings.push({
      ...warning,
      id: Date.now() + Math.random().toString(36).substr(2, 9)
    });
  }

  addRecommendation(recommendation) {
    this.results.recommendations.push(recommendation);
  }

  calculateScore() {
    // Ensure score is between 0-100
    this.results.safetyScore = Math.max(0, Math.min(100, this.results.safetyScore));
    
    // Determine safety level
    if (this.results.safetyScore >= 80) {
      this.results.safetyLevel = 'Very Safe';
      this.results.safetyColor = '#2ecc71'; // Green
    } else if (this.results.safetyScore >= 60) {
      this.results.safetyLevel = 'Moderately Safe';
      this.results.safetyColor = '#f39c12'; // Orange
    } else if (this.results.safetyScore >= 40) {
      this.results.safetyLevel = 'Caution Advised';
      this.results.safetyColor = '#e74c3c'; // Red
    } else {
      this.results.safetyLevel = 'Potentially Dangerous';
      this.results.safetyColor = '#c0392b'; // Dark Red
    }
    
    this.results.isSafe = this.results.safetyScore >= 60;
    
    // Add scan timestamp
    this.results.scanTime = Date.now();
    this.results.scanDuration = Date.now() - this.results.scanTime;
  }

  async sendResultsToBackground() {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'scanComplete',
        url: window.location.href,
        results: this.results
      });
      
      debugLog('Results sent to background:', response);
    } catch (error) {
      console.error('🔒 OmniProtect: Failed to send results:', error);
    }
  }

  updateSafetyIndicator() {
    if (safetyIndicator) {
      const color = this.results.isSafe ? '#2ecc71' : '#e74c3c';
      safetyIndicator.style.background = color;
      safetyIndicator.style.boxShadow = `0 4px 15px ${color}40`;
      
      // Update tooltip
      safetyIndicator.title = `OmniProtect: ${this.results.safetyScore}/100 - ${this.results.safetyLevel}\nClick for details`;
    }
  }

  // ====================
  // UI DISPLAY METHODS
  // ====================

  displayResults() {
    // Remove any existing safety panel
    const existingPanel = document.getElementById('omniprotect-safety-panel');
    if (existingPanel) existingPanel.remove();
    
    // Create safety panel
    const panel = document.createElement('div');
    panel.id = 'omniprotect-safety-panel';
    
    // Apply styles
    panel.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: white;
      border-radius: 10px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.15);
      padding: 20px;
      width: 350px;
      z-index: 1000000;
      font-family: 'Segoe UI', Arial, sans-serif;
      border-left: 5px solid ${this.results.safetyColor};
      animation: slideIn 0.3s ease;
      max-height: 80vh;
      overflow-y: auto;
      font-size: 14px;
    `;
    
    // Build panel content
    panel.innerHTML = this.getPanelHTML();
    
    // Add to page
    document.body.appendChild(panel);
    
    // Add event listeners
    this.setupPanelEvents(panel);
    
    // Auto-hide after 30 seconds
    setTimeout(() => {
      if (document.body.contains(panel)) {
        panel.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => panel.remove(), 300);
      }
    }, 30000);
    
    return panel;
  }

  getPanelHTML() {
    return `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <h3 style="margin: 0; color: #2c3e50; display: flex; align-items: center; gap: 10px; font-size: 16px;">
          <span style="color: ${this.results.safetyColor}; font-size: 20px;">🔒</span>
          OmniProtect Safety Scan
        </h3>
        <button id="close-panel" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #7f8c8d; line-height: 1;">×</button>
      </div>
      
      <div style="text-align: center; margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
        <div style="font-size: 48px; color: ${this.results.safetyColor}; font-weight: bold; line-height: 1;">
          ${this.results.safetyScore}/100
        </div>
        <div style="font-size: 18px; color: ${this.results.safetyColor}; font-weight: bold; margin: 5px 0;">
          ${this.results.safetyLevel}
        </div>
        <div style="color: #7f8c8d; font-size: 14px; margin-top: 5px;">
          ${this.results.isSafe ? '✅ This site appears safe' : '⚠️ Exercise caution on this site'}
        </div>
        <div style="font-size: 12px; color: #95a5a6; margin-top: 5px;">
          ${new URL(this.results.url).hostname}
        </div>
      </div>
      
      ${this.results.warnings.length > 0 ? `
        <div style="margin-bottom: 20px;">
          <h4 style="color: #e74c3c; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; font-size: 14px;">
            <span>⚠️</span> Safety Warnings (${this.results.warnings.length})
          </h4>
          <div style="max-height: 200px; overflow-y: auto; padding-right: 5px;">
            ${this.results.warnings.map(warning => `
              <div class="warning-item" style="background: #ffeaea; padding: 12px; margin-bottom: 8px; border-radius: 5px; border-left: 3px solid ${this.getSeverityColor(warning.severity)};">
                <div style="font-weight: bold; color: #c0392b; font-size: 13px;">${warning.message}</div>
                <div style="display: flex; justify-content: space-between; margin-top: 8px;">
                  <span style="font-size: 11px; color: #7f8c8d;">
                    Severity: <span style="color: ${this.getSeverityColor(warning.severity)}; font-weight: bold;">${warning.severity.toUpperCase()}</span>
                  </span>
                  <span style="font-size: 11px; color: #3498db;">${warning.type}</span>
                </div>
                ${warning.fix ? `
                  <div style="font-size: 11px; color: #27ae60; margin-top: 5px; padding: 4px; background: #e8f6ef; border-radius: 3px;">
                    💡 Fix: ${warning.fix}
                  </div>
                ` : ''}
              </div>
            `).join('')}
          </div>
        </div>
      ` : `
        <div style="text-align: center; padding: 20px; background: #e8f6ef; border-radius: 8px; margin-bottom: 20px;">
          <div style="font-size: 32px; color: #27ae60;">✅</div>
          <div style="color: #27ae60; font-weight: bold; margin: 10px 0;">No critical threats detected</div>
          <div style="color: #7f8c8d; font-size: 13px;">This site appears to be safe for browsing</div>
        </div>
      `}
      
      ${this.results.recommendations.length > 0 ? `
        <div style="margin-bottom: 20px;">
          <h4 style="color: #27ae60; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; font-size: 14px;">
            <span>✅</span> Positive Indicators (${this.results.recommendations.length})
          </h4>
          ${this.results.recommendations.map(rec => `
            <div style="background: #e8f6ef; padding: 10px; margin-bottom: 8px; border-radius: 5px; display: flex; align-items: center; gap: 10px;">
              <span style="color: #27ae60; font-size: 16px;">${rec.icon || '✅'}</span>
              <span style="color: #27ae60; font-size: 13px;">${rec.message}</span>
            </div>
          `).join('')}
        </div>
      ` : ''}
      
      <div style="font-size: 12px; color: #95a5a6; text-align: center; padding-top: 15px; border-top: 1px solid #ecf0f1;">
        Scanned: ${new Date(this.results.scanTime).toLocaleTimeString()}
        <br>
        <a href="#" id="toggle-details" style="color: #3498db; text-decoration: none; font-size: 11px;">Show technical details</a>
      </div>
      
      <div id="technical-details" style="display: none; margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 5px; font-size: 11px; max-height: 200px; overflow-y: auto;">
        <pre style="white-space: pre-wrap; word-wrap: break-word; margin: 0; font-family: 'Courier New', monospace;">${JSON.stringify(this.results, null, 2)}</pre>
      </div>
      
      <div style="margin-top: 15px; display: flex; gap: 10px;">
        <button id="rescan-btn" style="flex: 1; padding: 10px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 13px; font-weight: bold;">
          🔄 Rescan
        </button>
        <button id="report-btn" style="flex: 1; padding: 10px; background: ${this.results.isSafe ? '#2ecc71' : '#e74c3c'}; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 13px; font-weight: bold;">
          ${this.results.isSafe ? '✅ Mark Safe' : '🚨 Report Site'}
        </button>
      </div>
      
      <style>
        @keyframes slideIn {
          from { transform: translateX(400px); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(400px); opacity: 0; }
        }
        .warning-item:hover {
          transform: translateY(-2px);
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          transition: all 0.2s ease;
        }
      </style>
    `;
  }

  setupPanelEvents(panel) {
    // Close button
    panel.querySelector('#close-panel').addEventListener('click', () => {
      panel.style.animation = 'slideOut 0.3s ease';
      setTimeout(() => panel.remove(), 300);
    });
    
    // Rescan button
    panel.querySelector('#rescan-btn').addEventListener('click', () => {
      panel.remove();
      this.scan().then(() => this.displayResults());
    });
    
    // Report button
    panel.querySelector('#report-btn').addEventListener('click', () => {
      const action = this.results.isSafe ? 'safe' : 'report';
      if (action === 'report') {
        chrome.runtime.sendMessage({
          action: 'reportSite',
          url: this.results.url,
          results: this.results,
          reason: 'User reported from safety panel'
        });
        alert('🚨 Site reported to OmniProtect. Thank you for helping improve security!');
      } else {
        chrome.runtime.sendMessage({
          action: 'allowPage',
          url: this.results.url
        });
        alert('✅ Site marked as safe and added to whitelist.');
      }
      panel.remove();
    });
    
    // Toggle details
    panel.querySelector('#toggle-details').addEventListener('click', (e) => {
      e.preventDefault();
      const details = panel.querySelector('#technical-details');
      const link = e.target;
      if (details.style.display === 'none') {
        details.style.display = 'block';
        link.textContent = 'Hide technical details';
      } else {
        details.style.display = 'none';
        link.textContent = 'Show technical details';
      }
    });
  }

  getSeverityColor(severity) {
    const colors = {
      'critical': '#c0392b',
      'high': '#e74c3c',
      'medium': '#f39c12',
      'low': '#f1c40f'
    };
    return colors[severity] || '#95a5a6';
  }
}

// ====================
// SAFETY INDICATOR
// ====================

function createSafetyIndicator() {
  // Remove existing indicator
  const existingIndicator = document.getElementById('omniprotect-indicator');
  if (existingIndicator) existingIndicator.remove();
  
  // Create new indicator
  const indicator = document.createElement('div');
  indicator.id = 'omniprotect-indicator';
  safetyIndicator = indicator;
  
  // Apply styles
  indicator.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 60px;
    height: 60px;
    border-radius: 50%;
    background: #3498db;
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 28px;
    cursor: pointer;
    box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
    z-index: 999998;
    transition: all 0.3s ease;
    user-select: none;
  `;
  
  indicator.innerHTML = '🔒';
  indicator.title = 'OmniProtect Safety Scanner\nClick to view safety report';
  
  // Add hover effects
  indicator.addEventListener('mouseenter', () => {
    indicator.style.transform = 'scale(1.1)';
    indicator.style.boxShadow = '0 6px 20px rgba(52, 152, 219, 0.4)';
  });
  
  indicator.addEventListener('mouseleave', () => {
    indicator.style.transform = 'scale(1)';
  });
  
  // Add click handler
  indicator.addEventListener('click', () => {
    if (websiteScanner) {
      websiteScanner.displayResults();
    } else {
      websiteScanner = new WebsiteScanner();
      websiteScanner.scan().then(() => websiteScanner.displayResults());
    }
  });
  
  // Add pulsing animation for unsafe sites
  if (currentScanResults && !currentScanResults.isSafe) {
    indicator.style.animation = 'pulse 2s infinite';
    const style = document.createElement('style');
    style.textContent = `
      @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(231, 76, 60, 0.7); }
        70% { box-shadow: 0 0 0 10px rgba(231, 76, 60, 0); }
        100% { box-shadow: 0 0 0 0 rgba(231, 76, 60, 0); }
      }
    `;
    document.head.appendChild(style);
  }
  
  // Add to page
  document.body.appendChild(indicator);
  
  return indicator;
}

// ====================
// MESSAGE HANDLING
// ====================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  debugLog('Message received:', request);
  
  switch (request.action) {
    
    case 'ping':
      sendResponse({ status: 'active', from: 'content_script', url: window.location.href });
      break;
      
    case 'getSafetyResults':
      if (websiteScanner && websiteScanner.results) {
        sendResponse({ results: websiteScanner.results });
      } else {
        sendResponse({ error: 'No scan results available', url: window.location.href });
      }
      break;
      
    case 'performScan':
    case 'rescanPage':
    case 'autoScan':
      if (!websiteScanner) {
        websiteScanner = new WebsiteScanner();
      }
      websiteScanner.scan().then(results => {
        currentScanResults = results;
        sendResponse({ 
          scanned: true, 
          url: window.location.href,
          score: results.safetyScore,
          isSafe: results.isSafe
        });
      }).catch(error => {
        sendResponse({ error: 'Scan failed', details: error.message });
      });
      return true; // Keep channel open for async
      
    case 'showSafetyReport':
      if (websiteScanner) {
        websiteScanner.displayResults();
        sendResponse({ shown: true });
      } else {
        websiteScanner = new WebsiteScanner();
        websiteScanner.scan().then(() => {
          websiteScanner.displayResults();
          sendResponse({ shown: true });
        });
      }
      return true;
      
    case 'toggleFeature':
      // Handle feature toggling
      const enabled = request.enabled;
      if (enabled) {
        initializeScanner();
      } else {
        // Remove indicator and panel
        const indicator = document.getElementById('omniprotect-indicator');
        if (indicator) indicator.remove();
        const panel = document.getElementById('omniprotect-safety-panel');
        if (panel) panel.remove();
      }
      sendResponse({ toggled: true, enabled: enabled });
      break;
      
    case 'updateColor':
      // Handle color updates if needed
      sendResponse({ updated: true, color: request.color });
      break;
      
    case 'contextMenuClicked':
      // Handle context menu clicks
      if (websiteScanner) {
        websiteScanner.displayResults();
      }
      sendResponse({ handled: true });
      break;
      
    case 'startProtection':
      // Initialize protection on page
      initializeScanner();
      sendResponse({ protectionStarted: true, timestamp: Date.now() });
      break;
      
    case 'reinitialize':
      // Reinitialize scanner
      initializeScanner();
      sendResponse({ reinitialized: true, reason: request.reason });
      break;
      
    default:
      sendResponse({ 
        error: 'Unknown action in content script',
        received: request,
        availableActions: [
          'performScan', 'getSafetyResults', 'showSafetyReport',
          'toggleFeature', 'startProtection', 'reinitialize'
        ]
      });
  }
  
  return true; // Keep message channel open for async responses
});

// ====================
// INITIALIZATION
// ====================

async function initializeScanner() {
  debugLog('Initializing OmniProtect scanner...');
  
  try {
    // Check if protection is enabled
    const settings = await chrome.storage.sync.get(['protectionEnabled', 'autoScan']);
    
    if (settings.protectionEnabled !== false) {
      // Initialize scanner
      websiteScanner = new WebsiteScanner();
      
      // Create safety indicator
      createSafetyIndicator();
      
      // Start auto-scan if enabled
      if (settings.autoScan !== false) {
        setTimeout(async () => {
          const results = await websiteScanner.scan();
          currentScanResults = results;
          
          // Update popup if it's open
          chrome.runtime.sendMessage({
            action: 'scanUpdate',
            url: window.location.href,
            results: results
          }).catch(() => {
            // Popup might not be open - that's OK
          });
        }, 2000);
      }
      
      debugLog('OmniProtect scanner initialized');
    } else {
      debugLog('OmniProtect protection is disabled');
    }
  } catch (error) {
    console.error('🔒 OmniProtect: Initialization error:', error);
  }
}

// ====================
// GLOBAL EXPORT FOR TESTING
// ====================

// Make scanner available for testing from console
window.OmniProtect = {
  scanner: null,
  scan: async function() {
    if (!this.scanner) {
      this.scanner = new WebsiteScanner();
    }
    return await this.scanner.scan();
  },
  showReport: function() {
    if (this.scanner) {
      this.scanner.displayResults();
    } else {
      this.scanner = new WebsiteScanner();
      this.scanner.scan().then(() => this.scanner.displayResults());
    }
  },
  test: function() {
    console.log('🔒 OmniProtect Test Suite');
    console.log('1. Run scan: OmniProtect.scan()');
    console.log('2. Show report: OmniProtect.showReport()');
    console.log('3. Check results: OmniProtect.scanner.results');
  }
};

// Initialize when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeScanner);
} else {
  initializeScanner();
}

// Reinitialize if page becomes visible again
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    // Page is visible again, refresh scanner if needed
    if (websiteScanner && Date.now() - websiteScanner.results.scanTime > 300000) { // 5 minutes
      websiteScanner.scan();
    }
  }
});

// Listen for page changes in SPA (Single Page Applications)
let lastUrl = window.location.href;
const observer = new MutationObserver(() => {
  if (window.location.href !== lastUrl) {
    lastUrl = window.location.href;
    debugLog('URL changed in SPA:', lastUrl);
    
    // Reinitialize scanner for new page
    setTimeout(() => {
      if (websiteScanner) {
        websiteScanner.scan();
      } else {
        initializeScanner();
      }
    }, 1000);
  }
});

observer.observe(document, { subtree: true, childList: true });

console.log('🔒 OmniProtect: Content script initialization complete');