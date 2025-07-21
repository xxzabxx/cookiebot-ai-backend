/**
 * CookieBot.ai - Advanced Cookie Consent Management Platform
 * Version: 3.0.0
 * Author: Manus AI
 * License: MIT
 * 
 * Features:
 * - Complete dashboard configuration support
 * - Advanced styling and theming
 * - Multi-jurisdiction compliance (GDPR/CCPA/LGPD)
 * - Privacy Insights widget with full customization
 * - Automatic cookie detection and categorization
 * - Real-time analytics and revenue tracking
 */

(function(window, document) {
    'use strict';

    // Prevent multiple initializations
    if (window.CookieBotAI) {
        return;
    }

    /**
     * Main CookieBot.ai Class - Enhanced Version 3.0
     */
    class CookieBotAI {
        constructor(config = {}) {
            this.version = '3.0.0';
            this.config = this.mergeConfig(config);
            this.consent = {
                necessary: true,
                preferences: false,
                statistics: false,
                marketing: false,
                method: null,
                timestamp: null
            };
            this.cookies = [];
            this.isInitialized = false;
            this.bannerVisible = false;
            this.privacyInsights = [];
            this.privacyWidgetVisible = false;
            this.blockedCookies = [];
            
            // Event system
            this.events = {};
            
            // Initialize the system
            this.init();
        }

        /**
         * Enhanced configuration with ALL dashboard options
         */
        mergeConfig(userConfig) {
            const defaultConfig = {
                // Basic configuration
                domain: window.location.hostname,
                apiEndpoint: 'https://cookiebot-ai-backend.vercel.app/api',
                clientId: null,
                
                // Company branding
                companyName: '',
                logoUrl: null,
                showLogo: true,
                
                // Banner configuration
                bannerPosition: 'bottom', // top, bottom, center
                bannerStyle: 'modern', // modern, classic, minimal
                theme: 'light', // light, dark, custom
                
                // Styling (NEW - Dashboard configurable)
                primaryColor: '#007bff',
                backgroundColor: '#ffffff',
                textColor: '#333333',
                borderRadius: '8px',
                buttonStyle: 'default', // default, solid, outline
                
                // Compliance configuration (NEW)
                jurisdiction: 'auto', // auto, gdpr, ccpa, lgpd
                autoBlock: true,
                granularConsent: true,
                showDeclineButton: true,
                consentExpiry: 365, // days
                
                // Privacy Insights (Enhanced)
                enablePrivacyInsights: true,
                privacyInsightsFrequency: 3, // per session
                privacyWidgetDelay: 3000, // ms after consent
                privacyWidgetDuration: 15000, // ms display time
                revenueShare: 0.6, // 60% to website owner
                
                // Language and localization (NEW)
                language: 'auto', // auto, en, es, fr, de, etc.
                
                // Legacy support
                enableAffiliateAds: false, // Deprecated in favor of Privacy Insights
                
                // Callbacks
                onConsentGiven: null,
                onConsentChanged: null,
                onBannerShown: null,
                onBannerHidden: null,
                onPrivacyInsightShown: null,
                onPrivacyInsightClicked: null
            };

            return { ...defaultConfig, ...userConfig };
        }

        /**
         * Initialize the cookie consent system
         */
        async init() {
            if (this.isInitialized) return;

            try {
                // Load stored consent
                this.loadStoredConsent();
                
                // Detect cookies and scripts
                await this.detectCookies();
                
                // Apply auto-blocking if enabled
                if (this.config.autoBlock) {
                    this.applyAutoBlocking();
                }
                
                // Show banner if consent needed
                if (this.shouldShowBanner()) {
                    await this.showConsentBanner();
                }
                
                // Schedule Privacy Insights if consent given
                if (this.hasConsent() && this.config.enablePrivacyInsights) {
                    this.schedulePrivacyInsights();
                }
                
                this.isInitialized = true;
                this.trigger('initialized', { config: this.config });
                
            } catch (error) {
                console.error('CookieBot.ai initialization failed:', error);
            }
        }

        /**
         * Enhanced cookie detection with categorization
         */
        async detectCookies() {
            this.cookies = [];
            
            // Detect existing cookies
            const cookieStrings = document.cookie.split(';');
            for (let cookieString of cookieStrings) {
                if (cookieString.trim()) {
                    const [name, value] = cookieString.trim().split('=');
                    if (name) {
                        const cookie = {
                            name: name.trim(),
                            value: value || '',
                            category: this.categorizeCookie(name.trim()),
                            domain: window.location.hostname,
                            secure: document.location.protocol === 'https:',
                            timestamp: new Date().toISOString()
                        };
                        this.cookies.push(cookie);
                    }
                }
            }
            
            // Detect tracking scripts
            const scripts = document.querySelectorAll('script[src]');
            scripts.forEach(script => {
                const scriptInfo = this.categorizeScript(script.src);
                if (scriptInfo.category !== 'necessary') {
                    this.cookies.push({
                        name: scriptInfo.name,
                        value: script.src,
                        category: scriptInfo.category,
                        type: 'script',
                        element: script,
                        domain: new URL(script.src).hostname,
                        timestamp: new Date().toISOString()
                    });
                }
            });

            // Send cookie data to backend for analysis
            if (this.config.clientId && this.config.apiEndpoint) {
                await this.sendCookieData();
            }
        }

        /**
         * Enhanced cookie categorization
         */
        categorizeCookie(cookieName) {
            const name = cookieName.toLowerCase();
            
            // Necessary cookies
            if (name.includes('session') || name.includes('csrf') || name.includes('auth') || 
                name.includes('security') || name.includes('consent') || name.includes('cookiebot')) {
                return 'necessary';
            }
            
            // Marketing cookies
            if (name.includes('_ga') || name.includes('_gid') || name.includes('_fbp') || 
                name.includes('_fbc') || name.includes('ads') || name.includes('marketing') ||
                name.includes('utm') || name.includes('campaign')) {
                return 'marketing';
            }
            
            // Statistics cookies
            if (name.includes('analytics') || name.includes('stats') || name.includes('_gat') ||
                name.includes('collect') || name.includes('measure')) {
                return 'statistics';
            }
            
            // Preferences cookies
            if (name.includes('pref') || name.includes('settings') || name.includes('config') ||
                name.includes('theme') || name.includes('lang')) {
                return 'preferences';
            }
            
            return 'preferences'; // Default for unknown cookies
        }

        /**
         * Enhanced script categorization
         */
        categorizeScript(src) {
            const url = src.toLowerCase();
            
            // Google Analytics
            if (url.includes('google-analytics') || url.includes('googletagmanager') || url.includes('gtag')) {
                return { name: 'Google Analytics', category: 'statistics' };
            }
            
            // Facebook Pixel
            if (url.includes('facebook') || url.includes('fbevents')) {
                return { name: 'Facebook Pixel', category: 'marketing' };
            }
            
            // Other tracking scripts
            if (url.includes('hotjar') || url.includes('mixpanel') || url.includes('segment')) {
                return { name: this.extractScriptName(url), category: 'statistics' };
            }
            
            // Ad networks
            if (url.includes('doubleclick') || url.includes('adsystem') || url.includes('googlesyndication')) {
                return { name: this.extractScriptName(url), category: 'marketing' };
            }
            
            return { name: this.extractScriptName(url), category: 'preferences' };
        }

        /**
         * Extract readable script name from URL
         */
        extractScriptName(url) {
            try {
                const hostname = new URL(url).hostname;
                return hostname.replace('www.', '').split('.')[0];
            } catch {
                return 'Unknown Script';
            }
        }

        /**
         * NEW: Auto-blocking functionality
         */
        applyAutoBlocking() {
            if (!this.hasConsent()) {
                this.cookies.forEach(cookie => {
                    if (cookie.category !== 'necessary' && cookie.element) {
                        // Block script execution
                        cookie.element.type = 'text/plain';
                        cookie.element.setAttribute('data-cookiebot-blocked', 'true');
                        this.blockedCookies.push(cookie);
                    }
                });
            }
        }

        /**
         * NEW: Unblock cookies after consent
         */
        unblockCookies() {
            this.blockedCookies.forEach(cookie => {
                if (cookie.element && cookie.element.hasAttribute('data-cookiebot-blocked')) {
                    cookie.element.type = 'text/javascript';
                    cookie.element.removeAttribute('data-cookiebot-blocked');
                    
                    // Re-execute script
                    const newScript = document.createElement('script');
                    newScript.src = cookie.element.src;
                    cookie.element.parentNode.replaceChild(newScript, cookie.element);
                }
            });
            this.blockedCookies = [];
        }

        /**
         * NEW: Jurisdiction detection
         */
        detectJurisdiction() {
            if (this.config.jurisdiction !== 'auto') {
                return this.config.jurisdiction;
            }
            
            // Simple geo-detection based on timezone and language
            const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
            const language = navigator.language || navigator.userLanguage;
            
            // European timezones - GDPR
            if (timezone.includes('Europe/') || language.startsWith('de') || language.startsWith('fr')) {
                return 'gdpr';
            }
            
            // California timezone - CCPA
            if (timezone.includes('America/Los_Angeles') || timezone.includes('America/Pacific')) {
                return 'ccpa';
            }
            
            // Brazil timezone - LGPD
            if (timezone.includes('America/Sao_Paulo') || language.startsWith('pt')) {
                return 'lgpd';
            }
            
            return 'gdpr'; // Default to GDPR
        }

        /**
         * NEW: Language detection
         */
        detectLanguage() {
            if (this.config.language !== 'auto') {
                return this.config.language;
            }
            
            const lang = navigator.language || navigator.userLanguage || 'en';
            return lang.split('-')[0]; // Get base language code
        }

        /**
         * Enhanced banner display with new styling options
         */
        async showConsentBanner() {
            if (this.bannerVisible) return;

            const jurisdiction = this.detectJurisdiction();
            const language = this.detectLanguage();
            const texts = this.getLocalizedTexts(language, jurisdiction);

            // Create banner element with enhanced styling
            const banner = this.createBannerElement(texts, jurisdiction);
            
            // Apply custom styling
            this.applyCustomStyling(banner);
            
            // Add to page
            document.body.appendChild(banner);
            this.bannerVisible = true;
            
            // Attach event listeners
            this.attachBannerEvents(banner, jurisdiction);
            
            this.trigger('bannerShown', { jurisdiction, language });
        }

        /**
         * NEW: Enhanced banner creation with all styling options
         */
        createBannerElement(texts, jurisdiction) {
            const banner = document.createElement('div');
            banner.id = 'cookiebot-banner';
            banner.className = `cba-banner cba-${this.config.bannerPosition} cba-${this.config.theme} cba-${this.config.bannerStyle}`;
            
            // Generate banner HTML with enhanced options
            banner.innerHTML = this.generateBannerHTML(texts, jurisdiction);
            
            return banner;
        }

        /**
         * NEW: Enhanced HTML generation with all configuration options
         */
        generateBannerHTML(texts, jurisdiction) {
            const showGranular = this.config.granularConsent;
            const showDecline = this.config.showDeclineButton;
            const showLogo = this.config.showLogo && this.config.logoUrl;
            
            return `
                <div class="cba-container">
                    ${showLogo ? `<div class="cba-logo">
                        <img src="${this.config.logoUrl}" alt="${this.config.companyName}" />
                    </div>` : ''}
                    
                    <div class="cba-content">
                        <div class="cba-header">
                            <span class="cba-robot-icon">🤖</span>
                            <h3 class="cba-title">${texts.title}</h3>
                        </div>
                        
                        <p class="cba-description">${texts.description}</p>
                        
                        ${showGranular ? `
                            <div class="cba-categories">
                                <div class="cba-category">
                                    <label>
                                        <input type="checkbox" checked disabled> ${texts.necessary}
                                    </label>
                                </div>
                                <div class="cba-category">
                                    <label>
                                        <input type="checkbox" id="cba-preferences"> ${texts.preferences}
                                    </label>
                                </div>
                                <div class="cba-category">
                                    <label>
                                        <input type="checkbox" id="cba-statistics"> ${texts.statistics}
                                    </label>
                                </div>
                                <div class="cba-category">
                                    <label>
                                        <input type="checkbox" id="cba-marketing"> ${texts.marketing}
                                    </label>
                                </div>
                            </div>
                        ` : ''}
                    </div>
                    
                    <div class="cba-actions">
                        ${showDecline ? `<button class="cba-btn cba-btn-decline" id="cba-decline">${texts.decline}</button>` : ''}
                        ${showGranular ? `<button class="cba-btn cba-btn-save" id="cba-save">${texts.savePreferences}</button>` : ''}
                        <button class="cba-btn cba-btn-accept" id="cba-accept">${texts.acceptAll}</button>
                    </div>
                </div>
            `;
        }

        /**
         * NEW: Apply custom styling from dashboard configuration
         */
        applyCustomStyling(banner) {
            const style = document.createElement('style');
            style.textContent = this.generateCustomCSS();
            document.head.appendChild(style);
        }

        /**
         * NEW: Generate CSS based on configuration
         */
        generateCustomCSS() {
            const config = this.config;
            
            return `
                #cookiebot-banner {
                    --cba-primary-color: ${config.primaryColor};
                    --cba-background-color: ${config.backgroundColor};
                    --cba-text-color: ${config.textColor};
                    --cba-border-radius: ${config.borderRadius};
                }
                
                .cba-banner {
                    position: fixed;
                    z-index: 999999;
                    background: var(--cba-background-color);
                    color: var(--cba-text-color);
                    border-radius: var(--cba-border-radius);
                    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    max-width: 500px;
                    padding: 24px;
                    margin: 20px;
                }
                
                .cba-bottom { bottom: 0; left: 0; }
                .cba-top { top: 0; left: 0; }
                .cba-center { 
                    top: 50%; left: 50%; 
                    transform: translate(-50%, -50%);
                    margin: 0;
                }
                
                .cba-container {
                    display: flex;
                    flex-direction: column;
                    gap: 16px;
                }
                
                .cba-logo img {
                    height: 32px;
                    width: auto;
                }
                
                .cba-header {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                
                .cba-robot-icon {
                    font-size: 20px;
                }
                
                .cba-title {
                    margin: 0;
                    font-size: 18px;
                    font-weight: 600;
                }
                
                .cba-description {
                    margin: 0;
                    font-size: 14px;
                    line-height: 1.5;
                    opacity: 0.8;
                }
                
                .cba-categories {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 8px;
                    margin: 8px 0;
                }
                
                .cba-category label {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    font-size: 13px;
                    cursor: pointer;
                }
                
                .cba-actions {
                    display: flex;
                    gap: 12px;
                    flex-wrap: wrap;
                }
                
                .cba-btn {
                    padding: 10px 20px;
                    border: none;
                    border-radius: calc(var(--cba-border-radius) * 0.5);
                    font-size: 14px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    flex: 1;
                    min-width: 100px;
                }
                
                .cba-btn-accept {
                    background: var(--cba-primary-color);
                    color: white;
                }
                
                .cba-btn-decline, .cba-btn-save {
                    background: transparent;
                    color: var(--cba-text-color);
                    border: 1px solid var(--cba-primary-color);
                }
                
                .cba-btn:hover {
                    transform: translateY(-1px);
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }
                
                /* Button style variations */
                .cba-banner[data-button-style="solid"] .cba-btn-decline,
                .cba-banner[data-button-style="solid"] .cba-btn-save {
                    background: var(--cba-primary-color);
                    color: white;
                    opacity: 0.8;
                }
                
                .cba-banner[data-button-style="outline"] .cba-btn {
                    background: transparent;
                    border: 2px solid var(--cba-primary-color);
                    color: var(--cba-primary-color);
                }
                
                .cba-banner[data-button-style="outline"] .cba-btn-accept {
                    background: var(--cba-primary-color);
                    color: white;
                }
                
                /* Theme variations */
                .cba-dark {
                    --cba-background-color: #1f2937;
                    --cba-text-color: #f9fafb;
                }
                
                /* Responsive design */
                @media (max-width: 768px) {
                    .cba-banner {
                        left: 10px;
                        right: 10px;
                        max-width: none;
                        margin: 10px;
                    }
                    
                    .cba-categories {
                        grid-template-columns: 1fr;
                    }
                    
                    .cba-actions {
                        flex-direction: column;
                    }
                }
            `;
        }

        /**
         * NEW: Enhanced localized texts with jurisdiction-specific content
         */
        getLocalizedTexts(language, jurisdiction) {
            const texts = {
                en: {
                    title: `Your AI-Powered Cookie Consent Robot`,
                    description: `We use cookies to enhance your experience and provide personalized content. Our Privacy Insights system helps you understand data usage while earning revenue.`,
                    necessary: 'Necessary',
                    preferences: 'Preferences', 
                    statistics: 'Statistics',
                    marketing: 'Marketing',
                    acceptAll: 'Accept All',
                    decline: 'Decline',
                    savePreferences: 'Save Preferences'
                },
                es: {
                    title: 'Tu Robot de Consentimiento de Cookies con IA',
                    description: 'Utilizamos cookies para mejorar tu experiencia y proporcionar contenido personalizado.',
                    necessary: 'Necesarias',
                    preferences: 'Preferencias',
                    statistics: 'Estadísticas', 
                    marketing: 'Marketing',
                    acceptAll: 'Aceptar Todo',
                    decline: 'Rechazar',
                    savePreferences: 'Guardar Preferencias'
                },
                fr: {
                    title: 'Votre Robot de Consentement aux Cookies IA',
                    description: 'Nous utilisons des cookies pour améliorer votre expérience et fournir du contenu personnalisé.',
                    necessary: 'Nécessaires',
                    preferences: 'Préférences',
                    statistics: 'Statistiques',
                    marketing: 'Marketing', 
                    acceptAll: 'Tout Accepter',
                    decline: 'Refuser',
                    savePreferences: 'Sauvegarder'
                }
            };
            
            // Jurisdiction-specific adjustments
            const baseTexts = texts[language] || texts.en;
            
            if (jurisdiction === 'ccpa') {
                baseTexts.description = baseTexts.description.replace('cookies', 'cookies and personal information');
                baseTexts.decline = 'Do Not Sell My Info';
            }
            
            return baseTexts;
        }

        /**
         * Enhanced event attachment with new button types
         */
        attachBannerEvents(banner, jurisdiction) {
            // Accept all button
            const acceptBtn = banner.querySelector('#cba-accept');
            if (acceptBtn) {
                acceptBtn.addEventListener('click', () => this.acceptAll());
            }
            
            // Decline button (if enabled)
            const declineBtn = banner.querySelector('#cba-decline');
            if (declineBtn) {
                declineBtn.addEventListener('click', () => this.declineAll());
            }
            
            // Save preferences button (if granular consent enabled)
            const saveBtn = banner.querySelector('#cba-save');
            if (saveBtn) {
                saveBtn.addEventListener('click', () => this.savePreferences());
            }
        }

        /**
         * Enhanced accept all with unblocking
         */
        acceptAll() {
            this.consent = {
                necessary: true,
                preferences: true,
                statistics: true,
                marketing: true,
                method: 'accept_all',
                timestamp: new Date().toISOString()
            };
            
            this.saveConsent();
            this.unblockCookies();
            this.hideBanner();
            this.applyConsent();
            
            // Schedule Privacy Insights
            if (this.config.enablePrivacyInsights) {
                this.schedulePrivacyInsights();
            }
            
            this.trigger('consentGiven', this.consent);
        }

        /**
         * NEW: Enhanced decline functionality
         */
        declineAll() {
            this.consent = {
                necessary: true,
                preferences: false,
                statistics: false,
                marketing: false,
                method: 'decline_all',
                timestamp: new Date().toISOString()
            };
            
            this.saveConsent();
            this.hideBanner();
            this.applyConsent();
            
            this.trigger('consentGiven', this.consent);
        }

        /**
         * NEW: Save granular preferences
         */
        savePreferences() {
            const banner = document.getElementById('cookiebot-banner');
            
            this.consent = {
                necessary: true,
                preferences: banner.querySelector('#cba-preferences')?.checked || false,
                statistics: banner.querySelector('#cba-statistics')?.checked || false,
                marketing: banner.querySelector('#cba-marketing')?.checked || false,
                method: 'granular',
                timestamp: new Date().toISOString()
            };
            
            this.saveConsent();
            this.unblockCookies();
            this.hideBanner();
            this.applyConsent();
            
            // Schedule Privacy Insights if any consent given
            if (this.config.enablePrivacyInsights && (this.consent.preferences || this.consent.statistics || this.consent.marketing)) {
                this.schedulePrivacyInsights();
            }
            
            this.trigger('consentGiven', this.consent);
        }

        /**
         * Enhanced Privacy Insights with frequency control
         */
        schedulePrivacyInsights() {
            if (!this.config.enablePrivacyInsights) return;
            
            const sessionKey = 'cookiebot-privacy-insights-count';
            const currentCount = parseInt(sessionStorage.getItem(sessionKey) || '0');
            
            if (currentCount >= this.config.privacyInsightsFrequency) {
                return; // Already shown enough times this session
            }
            
            setTimeout(() => {
                this.showPrivacyInsights();
                sessionStorage.setItem(sessionKey, (currentCount + 1).toString());
            }, this.config.privacyWidgetDelay);
        }

        /**
         * Enhanced Privacy Insights widget
         */
        async showPrivacyInsights() {
            if (this.privacyWidgetVisible) return;
            
            try {
                // Get insights from backend
                const insights = await this.getPrivacyInsights();
                
                if (insights && insights.length > 0) {
                    const widget = this.createPrivacyInsightsWidget(insights[0]);
                    document.body.appendChild(widget);
                    this.privacyWidgetVisible = true;
                    
                    // Auto-hide after duration
                    setTimeout(() => {
                        this.hidePrivacyInsights();
                    }, this.config.privacyWidgetDuration);
                    
                    this.trigger('privacyInsightShown', insights[0]);
                }
            } catch (error) {
                console.error('Failed to show Privacy Insights:', error);
            }
        }

        /**
         * Enhanced Privacy Insights widget creation
         */
        createPrivacyInsightsWidget(insight) {
            const widget = document.createElement('div');
            widget.id = 'cookiebot-privacy-insights';
            widget.className = 'cba-privacy-widget';
            
            widget.innerHTML = `
                <div class="cba-widget-container">
                    <div class="cba-widget-header">
                        <span class="cba-widget-icon">🔒</span>
                        <h4 class="cba-widget-title">Privacy Insights</h4>
                        <button class="cba-widget-close" id="cba-widget-close">×</button>
                    </div>
                    <div class="cba-widget-content">
                        <h5>${insight.title}</h5>
                        <p>${insight.description}</p>
                        <a href="${insight.url}" target="_blank" class="cba-widget-link" id="cba-widget-link">
                            ${insight.linkText}
                        </a>
                    </div>
                </div>
            `;
            
            // Add widget styling
            this.addPrivacyInsightsCSS();
            
            // Attach events
            widget.querySelector('#cba-widget-close').addEventListener('click', () => {
                this.hidePrivacyInsights();
            });
            
            widget.querySelector('#cba-widget-link').addEventListener('click', () => {
                this.trackPrivacyInsightClick(insight);
            });
            
            return widget;
        }

        /**
         * Privacy Insights widget CSS
         */
        addPrivacyInsightsCSS() {
            if (document.getElementById('cba-privacy-insights-css')) return;
            
            const style = document.createElement('style');
            style.id = 'cba-privacy-insights-css';
            style.textContent = `
                .cba-privacy-widget {
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    width: 320px;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.15);
                    z-index: 999998;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    animation: slideInUp 0.3s ease-out;
                }
                
                @keyframes slideInUp {
                    from { transform: translateY(100%); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }
                
                .cba-widget-container {
                    padding: 20px;
                }
                
                .cba-widget-header {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    margin-bottom: 12px;
                }
                
                .cba-widget-icon {
                    font-size: 18px;
                }
                
                .cba-widget-title {
                    margin: 0;
                    font-size: 16px;
                    font-weight: 600;
                    color: #1f2937;
                    flex: 1;
                }
                
                .cba-widget-close {
                    background: none;
                    border: none;
                    font-size: 20px;
                    cursor: pointer;
                    color: #6b7280;
                    padding: 0;
                    width: 24px;
                    height: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                
                .cba-widget-content h5 {
                    margin: 0 0 8px 0;
                    font-size: 14px;
                    font-weight: 600;
                    color: #374151;
                }
                
                .cba-widget-content p {
                    margin: 0 0 12px 0;
                    font-size: 13px;
                    line-height: 1.4;
                    color: #6b7280;
                }
                
                .cba-widget-link {
                    display: inline-block;
                    background: ${this.config.primaryColor};
                    color: white;
                    text-decoration: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    font-size: 13px;
                    font-weight: 500;
                    transition: background 0.2s ease;
                }
                
                .cba-widget-link:hover {
                    background: ${this.adjustColor(this.config.primaryColor, -20)};
                }
                
                @media (max-width: 768px) {
                    .cba-privacy-widget {
                        left: 20px;
                        right: 20px;
                        width: auto;
                    }
                }
            `;
            
            document.head.appendChild(style);
        }

        /**
         * Utility function to adjust color brightness
         */
        adjustColor(color, amount) {
            const usePound = color[0] === '#';
            const col = usePound ? color.slice(1) : color;
            const num = parseInt(col, 16);
            let r = (num >> 16) + amount;
            let g = (num >> 8 & 0x00FF) + amount;
            let b = (num & 0x0000FF) + amount;
            r = r > 255 ? 255 : r < 0 ? 0 : r;
            g = g > 255 ? 255 : g < 0 ? 0 : g;
            b = b > 255 ? 255 : b < 0 ? 0 : b;
            return (usePound ? '#' : '') + (r << 16 | g << 8 | b).toString(16).padStart(6, '0');
        }

        /**
         * Get Privacy Insights from backend
         */
        async getPrivacyInsights() {
            try {
                const response = await fetch(`${this.config.apiEndpoint}/privacy-insights`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        clientId: this.config.clientId,
                        domain: this.config.domain,
                        consentData: this.consent,
                        revenueShare: this.config.revenueShare
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    return data.insights || [];
                }
            } catch (error) {
                console.error('Failed to fetch Privacy Insights:', error);
            }
            
            // Fallback insights
            return this.getDefaultPrivacyInsights();
        }

        /**
         * Default Privacy Insights content
         */
        getDefaultPrivacyInsights() {
            return [{
                title: "Understanding Your Data",
                description: "Learn how websites use cookies to improve your browsing experience and protect your privacy.",
                url: "https://cookiebot.ai/privacy-education",
                linkText: "Learn More"
            }];
        }

        /**
         * Track Privacy Insight clicks for revenue
         */
        async trackPrivacyInsightClick(insight) {
            try {
                await fetch(`${this.config.apiEndpoint}/privacy-insight-click`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        clientId: this.config.clientId,
                        domain: this.config.domain,
                        insightId: insight.id,
                        revenueShare: this.config.revenueShare,
                        timestamp: new Date().toISOString()
                    })
                });
                
                this.trigger('privacyInsightClicked', insight);
            } catch (error) {
                console.error('Failed to track Privacy Insight click:', error);
            }
        }

        /**
         * Hide Privacy Insights widget
         */
        hidePrivacyInsights() {
            const widget = document.getElementById('cookiebot-privacy-insights');
            if (widget) {
                widget.style.animation = 'slideOutDown 0.3s ease-in';
                setTimeout(() => {
                    widget.remove();
                    this.privacyWidgetVisible = false;
                }, 300);
            }
        }

        /**
         * Enhanced consent storage with expiry
         */
        saveConsent() {
            const consentData = {
                ...this.consent,
                version: this.version,
                expiryDate: new Date(Date.now() + (this.config.consentExpiry * 24 * 60 * 60 * 1000)).toISOString()
            };
            
            localStorage.setItem('cookiebot-consent', JSON.stringify(consentData));
            localStorage.setItem('cookiebot-consent-timestamp', Date.now().toString());
        }

        /**
         * Enhanced consent loading with expiry check
         */
        loadStoredConsent() {
            try {
                const stored = localStorage.getItem('cookiebot-consent');
                if (stored) {
                    const consentData = JSON.parse(stored);
                    
                    // Check if consent has expired
                    if (consentData.expiryDate && new Date(consentData.expiryDate) < new Date()) {
                        this.clearStoredConsent();
                        return;
                    }
                    
                    this.consent = {
                        necessary: consentData.necessary || true,
                        preferences: consentData.preferences || false,
                        statistics: consentData.statistics || false,
                        marketing: consentData.marketing || false,
                        method: consentData.method || null,
                        timestamp: consentData.timestamp || null
                    };
                }
            } catch (error) {
                console.error('Failed to load stored consent:', error);
                this.clearStoredConsent();
            }
        }

        /**
         * Clear expired consent
         */
        clearStoredConsent() {
            localStorage.removeItem('cookiebot-consent');
            localStorage.removeItem('cookiebot-consent-timestamp');
            sessionStorage.removeItem('cookiebot-privacy-insights-count');
        }

        /**
         * Enhanced cookie data sending
         */
        async sendCookieData() {
            try {
                const response = await fetch(`${this.config.apiEndpoint}/cookie-scan`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        clientId: this.config.clientId,
                        domain: this.config.domain,
                        cookies: this.cookies,
                        consent: this.consent,
                        jurisdiction: this.detectJurisdiction(),
                        timestamp: new Date().toISOString(),
                        version: this.version
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    this.trigger('cookieDataSent', result);
                }
            } catch (error) {
                console.error('Failed to send cookie data:', error);
            }
        }

        /**
         * Check if banner should be shown
         */
        shouldShowBanner() {
            return !this.hasConsent();
        }

        /**
         * Check if user has given consent
         */
        hasConsent() {
            return this.consent.timestamp !== null;
        }

        /**
         * Get current consent status
         */
        getConsent() {
            return { ...this.consent };
        }

        /**
         * Get detected cookies
         */
        getCookies() {
            return [...this.cookies];
        }

        /**
         * Hide consent banner
         */
        hideBanner() {
            const banner = document.getElementById('cookiebot-banner');
            if (banner) {
                banner.style.animation = 'fadeOut 0.3s ease-in';
                setTimeout(() => {
                    banner.remove();
                    this.bannerVisible = false;
                    this.trigger('bannerHidden');
                }, 300);
            }
        }

        /**
         * Apply consent decisions
         */
        applyConsent() {
            // Implementation for applying consent decisions
            this.trigger('consentApplied', this.consent);
        }

        /**
         * Event system
         */
        on(event, callback) {
            if (!this.events[event]) {
                this.events[event] = [];
            }
            this.events[event].push(callback);
        }

        trigger(event, data = null) {
            if (this.events[event]) {
                this.events[event].forEach(callback => {
                    try {
                        callback(data);
                    } catch (error) {
                        console.error(`Error in event callback for ${event}:`, error);
                    }
                });
            }
            
            // Call config callbacks
            const callbackName = `on${event.charAt(0).toUpperCase()}${event.slice(1)}`;
            if (this.config[callbackName] && typeof this.config[callbackName] === 'function') {
                try {
                    this.config[callbackName](data);
                } catch (error) {
                    console.error(`Error in config callback ${callbackName}:`, error);
                }
            }
        }

        /**
         * Renew consent (force show banner)
         */
        renew() {
            this.clearStoredConsent();
            this.consent = {
                necessary: true,
                preferences: false,
                statistics: false,
                marketing: false,
                method: null,
                timestamp: null
            };
            this.showConsentBanner();
        }
    }

    // Auto-initialize if configuration is provided via script attributes
    const script = document.currentScript || document.querySelector('script[data-cbid]');
    if (script) {
        const config = {};
        
        // Extract ALL configuration from script attributes
        if (script.dataset.cbid) config.clientId = script.dataset.cbid;
        if (script.dataset.apiEndpoint) config.apiEndpoint = script.dataset.apiEndpoint;
        if (script.dataset.companyName) config.companyName = script.dataset.companyName;
        if (script.dataset.logoUrl) config.logoUrl = script.dataset.logoUrl;
        if (script.dataset.bannerPosition) config.bannerPosition = script.dataset.bannerPosition;
        if (script.dataset.bannerStyle) config.bannerStyle = script.dataset.bannerStyle;
        if (script.dataset.theme) config.theme = script.dataset.theme;
        if (script.dataset.primaryColor) config.primaryColor = script.dataset.primaryColor;
        if (script.dataset.backgroundColor) config.backgroundColor = script.dataset.backgroundColor;
        if (script.dataset.textColor) config.textColor = script.dataset.textColor;
        if (script.dataset.borderRadius) config.borderRadius = script.dataset.borderRadius;
        if (script.dataset.buttonStyle) config.buttonStyle = script.dataset.buttonStyle;
        if (script.dataset.jurisdiction) config.jurisdiction = script.dataset.jurisdiction;
        if (script.dataset.complianceMode) config.jurisdiction = script.dataset.complianceMode; // Alternative name
        if (script.dataset.autoBlock) config.autoBlock = script.dataset.autoBlock === 'true';
        if (script.dataset.granularConsent) config.granularConsent = script.dataset.granularConsent === 'true';
        if (script.dataset.showDecline) config.showDeclineButton = script.dataset.showDecline === 'true';
        if (script.dataset.consentExpiry) config.consentExpiry = parseInt(script.dataset.consentExpiry);
        if (script.dataset.enablePrivacyInsights) config.enablePrivacyInsights = script.dataset.enablePrivacyInsights !== 'false';
        if (script.dataset.privacyInsightsFrequency) config.privacyInsightsFrequency = parseInt(script.dataset.privacyInsightsFrequency);
        if (script.dataset.revenueShare) config.revenueShare = parseFloat(script.dataset.revenueShare);
        if (script.dataset.language) config.language = script.dataset.language;
        
        // Legacy support
        if (script.dataset.enableAffiliateAds) config.enableAffiliateAds = script.dataset.enableAffiliateAds === 'true';
        
        // Initialize CookieBot.ai with enhanced configuration
        window.CookieBotAI = new CookieBotAI(config);
    } else {
        // Expose class for manual initialization
        window.CookieBotAI = CookieBotAI;
    }

})(window, document);

