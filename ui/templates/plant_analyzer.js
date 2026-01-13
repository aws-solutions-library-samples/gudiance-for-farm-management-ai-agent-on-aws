/**
 * WhatsApp-Style Plant Analysis Chat Interface
 * Handles chat flow, API calls, and user interactions
 */

class PlantChatApp {
    constructor() {
        this.currentFile = null;
        this.chatState = {
            hasAnalysis: false,
            recommendedFertilizer: null,
            conversationActive: false
        };
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkRuntimeStatus();
        this.loadChatState();
    }

    bindEvents() {
        // Option button clicks
        document.addEventListener('click', (e) => {
            if (e.target.closest('.option-button')) {
                const action = e.target.closest('.option-button').dataset.action;
                this.handleOptionClick(action);
            }
        });

        // Modal events
        const uploadModal = document.getElementById('upload-modal');
        const closeModal = document.getElementById('close-modal');
        const cancelUpload = document.getElementById('cancel-upload');
        const uploadArea = document.getElementById('upload-area');
        const fileInput = document.getElementById('file-input');
        const uploadButton = document.getElementById('upload-button');

        closeModal?.addEventListener('click', () => this.closeModal());
        cancelUpload?.addEventListener('click', () => this.closeModal());
        uploadArea?.addEventListener('click', () => fileInput?.click());
        fileInput?.addEventListener('change', (e) => this.handleFileSelect(e));
        uploadButton?.addEventListener('click', () => this.uploadAndAnalyze());

        // Drag and drop
        uploadArea?.addEventListener('dragover', (e) => this.handleDragOver(e));
        uploadArea?.addEventListener('dragleave', (e) => this.handleDragLeave(e));
        uploadArea?.addEventListener('drop', (e) => this.handleDrop(e));

        // Input area events (for future text input)
        const messageInput = document.getElementById('message-input');
        const sendButton = document.getElementById('send-button');
        
        messageInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });
        
        sendButton?.addEventListener('click', () => this.sendMessage());
    }

    checkRuntimeStatus() {
        if (!window.RUNTIME_CONFIGURED) {
            this.showError('Runtime not configured. Please check your setup.');
            this.disableOptions();
        }
    }

    async loadChatState() {
        try {
            const response = await fetch('/api/chat-state');
            const state = await response.json();
            this.chatState = { ...this.chatState, ...state };
        } catch (error) {
            console.warn('Could not load chat state:', error);
        }
    }

    handleOptionClick(action) {
        this.addUserMessage(this.getOptionText(action));
        
        switch (action) {
            case 'analyze':
                this.showUploadModal();
                break;
            case 'history':
                this.retrieveHistory();
                break;
            case 'order':
                this.orderFertilizer();
                break;
        }
        
        this.hideInitialOptions();
    }

    getOptionText(action) {
        const texts = {
            'analyze': '🌱 Upload an image for analysis',
            'history': '📋 Retrieve old analysis',
            'order': '🛒 Buy Fertilizer'
        };
        return texts[action] || action;
    }

    showUploadModal() {
        const modal = document.getElementById('upload-modal');
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
        
        // Reset current file state and upload area
        this.currentFile = null;
        this.resetUploadArea();
        
        // Clear the file input
        const fileInput = document.getElementById('file-input');
        if (fileInput) {
            fileInput.value = '';
        }
    }

    closeModal() {
        const modal = document.getElementById('upload-modal');
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
        
        // Reset upload state
        this.currentFile = null;
        this.resetUploadArea();
        
        // Clear the file input
        const fileInput = document.getElementById('file-input');
        if (fileInput) {
            fileInput.value = '';
        }
    }

    handleFileSelect(event) {
        console.log('📁 File select event triggered');
        const file = event.target.files[0];
        console.log('📁 Selected file:', file);
        
        if (file) {
            console.log('📁 File details:', {
                name: file.name,
                size: file.size,
                type: file.type
            });
            this.validateAndSetFile(file);
        } else {
            console.log('❌ No file in event');
        }
    }

    handleDragOver(event) {
        event.preventDefault();
        event.target.closest('.upload-area').classList.add('dragover');
    }

    handleDragLeave(event) {
        event.target.closest('.upload-area').classList.remove('dragover');
    }

    handleDrop(event) {
        event.preventDefault();
        const uploadArea = event.target.closest('.upload-area');
        uploadArea.classList.remove('dragover');
        
        const files = event.dataTransfer.files;
        if (files.length > 0) {
            this.validateAndSetFile(files[0]);
        }
    }

    validateAndSetFile(file) {
        console.log('✅ Validating file:', file.name);
        
        // Check file type
        if (!file.type.startsWith('image/')) {
            console.error('❌ Invalid file type:', file.type);
            this.showError('Please select an image file (JPG, PNG, GIF)');
            return;
        }

        // Check file size (16MB limit)
        if (file.size > 16 * 1024 * 1024) {
            console.error('❌ File too large:', file.size);
            this.showError('File size must be less than 16MB');
            return;
        }

        console.log('✅ File validation passed');
        this.currentFile = file;
        this.updateUploadArea(file);
        
        // Enable upload button
        const uploadButton = document.getElementById('upload-button');
        uploadButton.disabled = false;
        console.log('✅ Upload button enabled');
    }

    updateUploadArea(file) {
        const uploadArea = document.getElementById('upload-area');
        const uploadIcon = uploadArea.querySelector('.upload-icon');
        const uploadText = uploadArea.querySelector('.upload-text');
        const uploadInfo = uploadArea.querySelector('.upload-info');
        
        if (uploadIcon) uploadIcon.textContent = '✅';
        if (uploadText) {
            uploadText.innerHTML = '';
            const strong = document.createElement('strong');
            strong.textContent = `File selected: ${file.name}`;
            const br = document.createElement('br');
            const sizeText = document.createTextNode(`Size: ${this.formatFileSize(file.size)}`);
            
            uploadText.appendChild(strong);
            uploadText.appendChild(br);
            uploadText.appendChild(sizeText);
        }
        if (uploadInfo) {
            uploadInfo.textContent = 'Click "Upload & Analyze" to proceed';
        }
    }

    resetUploadArea() {
        const uploadArea = document.getElementById('upload-area');
        const uploadIcon = uploadArea.querySelector('.upload-icon');
        const uploadText = uploadArea.querySelector('.upload-text');
        const uploadInfo = uploadArea.querySelector('.upload-info');
        
        if (uploadIcon) uploadIcon.textContent = '📷';
        if (uploadText) {
            uploadText.innerHTML = '';
            const strong = document.createElement('strong');
            strong.textContent = 'Drop your plant image here';
            const br = document.createElement('br');
            const clickText = document.createTextNode('or click to select a file');
            
            uploadText.appendChild(strong);
            uploadText.appendChild(br);
            uploadText.appendChild(clickText);
        }
        if (uploadInfo) {
            uploadInfo.textContent = 'Supports: JPG, PNG, GIF (max 16MB)';
        }
        
        const uploadButton = document.getElementById('upload-button');
        uploadButton.disabled = true;
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async uploadAndAnalyze() {
        console.log('🚀 Upload and analyze started');
        console.log('Current file:', this.currentFile);
        
        if (!this.currentFile) {
            console.error('❌ No file selected');
            this.showError('No file selected. Please select an image first.');
            return;
        }

        // Store file reference before closing modal (which resets currentFile)
        const fileToUpload = this.currentFile;
        
        this.closeModal();
        this.showTyping();

        try {
            const formData = new FormData();
            formData.append('image', fileToUpload);
            
            console.log('📦 FormData created with file:', fileToUpload.name);
            console.log('📦 File size:', fileToUpload.size);
            console.log('📦 File type:', fileToUpload.type);

            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });

            console.log('📡 Response received:', response.status);
            const result = await response.json();
            console.log('📄 Result:', result);
            
            this.hideTyping();

            if (result.status === 'success') {
                await this.displayAnalysisResult(result);
                this.chatState.hasAnalysis = true;
                this.chatState.recommendedFertilizer = result.recommended_fertilizer;
                this.showFollowupOptions();
            } else {
                this.showError(result.error || 'Analysis failed');
                this.showFollowupOptions();
            }

        } catch (error) {
            console.error('❌ Upload error:', error);
            this.hideTyping();
            this.showError('Network error. Please try again.');
            this.showFollowupOptions();
        }
    }

    async retrieveHistory() {
        this.showTyping();

        try {
            const response = await fetch('/api/history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();
            this.hideTyping();

            if (result.status === 'success') {
                this.displayHistoryResult(result);
                this.showFollowupOptions();
            } else {
                this.showError(result.error || 'Could not retrieve history');
                this.showFollowupOptions();
            }

        } catch (error) {
            this.hideTyping();
            this.showError('Network error. Please try again.');
            this.showFollowupOptions();
        }
    }

    async orderFertilizer() {
        this.showTyping();

        try {
            const response = await fetch('/api/order', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();
            this.hideTyping();

            if (result.status === 'success') {
                this.displayOrderResult(result);
                this.showFollowupOptions();
            } else {
                this.showError(result.error || 'Order failed');
                this.showFollowupOptions();
            }

        } catch (error) {
            this.hideTyping();
            this.showError('Network error. Please try again.');
            this.showFollowupOptions();
        }
    }

    async displayAnalysisResult(result) {
        // Show plant identification first
        if (result.plant_type && result.plant_type !== 'Unknown') {
            const plantContent = this.createAgentResponse('🌱', 'Plant Identification', 
                `Identified Plant: ${result.plant_type}`, 'plant-identification');
            await this.addAgentMessage(plantContent, 'plant-identification');
        }

        // Show health assessment
        if (result.health_issues) {
            const healthContent = this.createAgentResponse('🔍', 'Health Assessment Agent', 
                result.health_issues, 'health-assessment');
            await this.addAgentMessage(healthContent, 'health-assessment');
        }

        // Show expert advice
        if (result.expert_advice) {
            const expertContent = this.createAgentResponse('💡', 'Expert Consultation Agent', 
                result.expert_advice, 'expert-advice', true);
            await this.addAgentMessage(expertContent, 'expert-advice');
        }

        // Show fertilizer recommendation
        if (result.recommended_fertilizer) {
            const fertilizerContent = this.createAgentResponse('🌿', 'Fertilizer Recommendation Agent', 
                `Recommended: ${result.recommended_fertilizer}`, 'fertilizer-recommendation');
            await this.addAgentMessage(fertilizerContent, 'fertilizer-recommendation');
        }
    }

    displayHistoryResult(result) {
        const content = this.createResultSection('📋 Analysis History', 
            result.final_report || 'No previous analyses found.', true);
        this.addBotMessage(content);
    }

    displayOrderResult(result) {
        // Handle different order statuses
        let statusMessage = '';
        let statusClass = '';
        
        if (result.order_status === 'session_started') {
            statusMessage = '🚀 Browser session started! Fertilizer ordering is running in the background.';
            statusClass = 'status-started';
        } else if (result.order_status === 'completed') {
            statusMessage = '✅ Fertilizer ordering process completed!';
            statusClass = 'status-completed';
        } else if (result.order_status === 'error') {
            statusMessage = '❌ Fertilizer ordering failed. Please try again.';
            statusClass = 'status-error';
        } else {
            statusMessage = result.order_status || 'Order processing...';
            statusClass = 'status-processing';
        }

        const content = this.createOrderResultContent(result, statusMessage, statusClass);
        this.addBotMessage(content);
    }

    addUserMessage(text) {
        const messagesArea = document.getElementById('messages-area');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message user-message';
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        
        const messageText = document.createElement('div');
        messageText.className = 'message-text';
        messageText.textContent = text;
        
        const messageTime = document.createElement('div');
        messageTime.className = 'message-time';
        messageTime.textContent = this.getCurrentTime();
        
        messageContent.appendChild(messageText);
        messageContent.appendChild(messageTime);
        messageDiv.appendChild(messageContent);
        messagesArea.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addAgentMessage(content, agentType) {
        const messagesArea = document.getElementById('messages-area');
        const messageDiv = document.createElement('div');
        messageDiv.className = `message agent-message ${agentType}`;
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        
        const messageText = document.createElement('div');
        messageText.className = 'message-text';
        messageText.innerHTML = content; // content is already safe HTML from our DOM methods
        
        const messageTime = document.createElement('div');
        messageTime.className = 'message-time';
        messageTime.textContent = this.getCurrentTime();
        
        messageContent.appendChild(messageText);
        messageContent.appendChild(messageTime);
        messageDiv.appendChild(messageContent);
        messagesArea.appendChild(messageDiv);
        this.scrollToBottom();
        
        // Add a small delay between messages for better UX
        return new Promise(resolve => setTimeout(resolve, 500));
    }

    addBotMessage(content) {
        const messagesArea = document.getElementById('messages-area');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message bot-message';
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        
        const messageText = document.createElement('div');
        messageText.className = 'message-text';
        messageText.innerHTML = content; // content is already safe HTML from our DOM methods
        
        const messageTime = document.createElement('div');
        messageTime.className = 'message-time';
        messageTime.textContent = this.getCurrentTime();
        
        messageContent.appendChild(messageText);
        messageContent.appendChild(messageTime);
        messageDiv.appendChild(messageContent);
        messagesArea.appendChild(messageDiv);
        this.scrollToBottom();
    }

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = `❌ ${message}`;
        this.addBotMessage(errorDiv.outerHTML);
    }

    showTyping() {
        const typingIndicator = document.getElementById('typing-indicator');
        typingIndicator.style.display = 'flex';
        this.scrollToBottom();
    }

    hideTyping() {
        const typingIndicator = document.getElementById('typing-indicator');
        typingIndicator.style.display = 'none';
    }

    hideInitialOptions() {
        const initialOptions = document.getElementById('initial-options');
        if (initialOptions) {
            initialOptions.style.display = 'none';
        }
    }

    showFollowupOptions() {
        const messagesArea = document.getElementById('messages-area');
        const followupTemplate = document.getElementById('followup-template');
        
        if (followupTemplate) {
            const followupOptions = followupTemplate.cloneNode(true);
            followupOptions.id = 'followup-options-' + Date.now();
            followupOptions.style.display = 'flex';
            messagesArea.appendChild(followupOptions);
            this.scrollToBottom();
        }
    }

    disableOptions() {
        const optionButtons = document.querySelectorAll('.option-button');
        optionButtons.forEach(button => {
            button.style.opacity = '0.5';
            button.style.pointerEvents = 'none';
        });
    }

    getCurrentTime() {
        const now = new Date();
        return now.toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    }

    createAgentResponse(icon, agentName, content, responseClass, isPreformatted = false) {
        const responseDiv = document.createElement('div');
        responseDiv.className = `agent-response ${responseClass}`;
        
        const headerDiv = document.createElement('div');
        headerDiv.className = 'agent-header';
        
        const iconSpan = document.createElement('span');
        iconSpan.className = 'agent-icon';
        iconSpan.textContent = icon;
        
        const nameSpan = document.createElement('span');
        nameSpan.className = 'agent-name';
        nameSpan.textContent = agentName;
        
        headerDiv.appendChild(iconSpan);
        headerDiv.appendChild(nameSpan);
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'agent-content';
        
        if (isPreformatted) {
            const pre = document.createElement('pre');
            pre.className = 'expert-text';
            pre.textContent = content;
            contentDiv.appendChild(pre);
        } else {
            contentDiv.textContent = content;
        }
        
        responseDiv.appendChild(headerDiv);
        responseDiv.appendChild(contentDiv);
        
        return responseDiv.outerHTML;
    }

    createResultSection(title, content, isPreformatted = false) {
        const resultDiv = document.createElement('div');
        resultDiv.className = 'analysis-result';
        
        const sectionDiv = document.createElement('div');
        sectionDiv.className = 'result-section';
        
        const titleDiv = document.createElement('div');
        titleDiv.className = 'result-title';
        titleDiv.textContent = title;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'result-content';
        
        if (isPreformatted) {
            const pre = document.createElement('pre');
            pre.textContent = content;
            contentDiv.appendChild(pre);
        } else {
            contentDiv.textContent = content;
        }
        
        sectionDiv.appendChild(titleDiv);
        sectionDiv.appendChild(contentDiv);
        resultDiv.appendChild(sectionDiv);
        
        return resultDiv.outerHTML;
    }

    createOrderResultContent(result, statusMessage, statusClass) {
        const resultDiv = document.createElement('div');
        resultDiv.className = 'analysis-result';
        
        // Order Status Section
        const statusSection = document.createElement('div');
        statusSection.className = 'result-section';
        
        const statusTitle = document.createElement('div');
        statusTitle.className = 'result-title';
        statusTitle.textContent = '🛒 Order Status';
        
        const statusContent = document.createElement('div');
        statusContent.className = `result-content ${statusClass}`;
        statusContent.textContent = statusMessage;
        
        statusSection.appendChild(statusTitle);
        statusSection.appendChild(statusContent);
        resultDiv.appendChild(statusSection);
        
        // Live Session Section (if URL exists)
        if (result.live_session_url && this.isValidUrl(result.live_session_url)) {
            const liveSection = this.createLiveSessionSection(result.live_session_url);
            resultDiv.appendChild(liveSection);
        }
        
        // Message Section
        if (result.message) {
            const messageSection = this.createSimpleSection('💬 Message', result.message);
            resultDiv.appendChild(messageSection);
        }
        
        // Product Section
        if (result.recommended_fertilizer) {
            const productSection = this.createSimpleSection('🌿 Product', result.recommended_fertilizer);
            resultDiv.appendChild(productSection);
        }
        
        // Details Section
        if (result.final_report) {
            const detailsSection = this.createSimpleSection('📄 Details', result.final_report, true);
            resultDiv.appendChild(detailsSection);
        }
        
        return resultDiv.outerHTML;
    }

    createLiveSessionSection(url) {
        const section = document.createElement('div');
        section.className = 'result-section live-session-section';
        
        const title = document.createElement('div');
        title.className = 'result-title';
        title.textContent = '🌐 Watch Live Browser Automation';
        
        const content = document.createElement('div');
        content.className = 'result-content';
        
        const info = document.createElement('div');
        info.className = 'live-session-info';
        
        const p1 = document.createElement('p');
        p1.textContent = 'Click the button below to watch the Amazon ordering process in real-time:';
        
        const link = document.createElement('a');
        link.href = url;
        link.target = '_blank';
        link.className = 'live-session-button';
        link.textContent = '👀 Watch Live Automation';
        
        // Add secure event listener instead of onclick
        link.addEventListener('click', () => {
            link.textContent = '🔄 Opening browser viewer...';
            setTimeout(() => {
                link.textContent = '👀 Watch Live Automation';
            }, 2000);
        });
        
        const p2 = document.createElement('p');
        p2.className = 'live-session-note';
        const small = document.createElement('small');
        small.textContent = '💡 The browser automation will continue in the background. You can watch the entire Amazon login and checkout process live!';
        p2.appendChild(small);
        
        info.appendChild(p1);
        info.appendChild(link);
        info.appendChild(p2);
        content.appendChild(info);
        section.appendChild(title);
        section.appendChild(content);
        
        return section;
    }

    createSimpleSection(title, content, isPreformatted = false) {
        const section = document.createElement('div');
        section.className = 'result-section';
        
        const titleDiv = document.createElement('div');
        titleDiv.className = 'result-title';
        titleDiv.textContent = title;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'result-content';
        
        if (isPreformatted) {
            const pre = document.createElement('pre');
            pre.textContent = content;
            contentDiv.appendChild(pre);
        } else {
            contentDiv.textContent = content;
        }
        
        section.appendChild(titleDiv);
        section.appendChild(contentDiv);
        
        return section;
    }

    isValidUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    }

    scrollToBottom() {
        const messagesArea = document.getElementById('messages-area');
        setTimeout(() => {
            messagesArea.scrollTop = messagesArea.scrollHeight;
        }, 100);
    }

    sendMessage() {
        // Future implementation for text-based interactions
        const messageInput = document.getElementById('message-input');
        const message = messageInput.value.trim();
        
        if (message) {
            this.addUserMessage(message);
            messageInput.value = '';
            
            // Process message (future enhancement)
            this.processTextMessage(message);
        }
    }

    processTextMessage(message) {
        // Future implementation for handling text messages
        // Could include follow-up questions, clarifications, etc.
        this.showTyping();
        
        setTimeout(() => {
            this.hideTyping();
            this.addBotMessage("I understand you want to chat! For now, please use the option buttons above to interact with me. Text chat coming soon! 😊");
        }, 1000);
    }
}

// Initialize the chat app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PlantChatApp();
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        // Refresh chat state when page becomes visible
        const app = window.plantChatApp;
        if (app) {
            app.loadChatState();
        }
    }
});

// Export for global access
window.PlantChatApp = PlantChatApp;
