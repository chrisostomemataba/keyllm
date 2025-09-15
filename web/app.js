const token = localStorage.getItem('token');
const email = localStorage.getItem('email') || 'admin@local';
if (!token) {
    window.location.href = '/web/login.html';
}

// State management
let models = []; // Cache for dropdown
let latencyChart = null;
let currentChatModelId = null;
let chatMessages = [];

// DOM elements
const modelDialog = document.getElementById('modelDialog');
const modelForm = document.getElementById('addModelForm');
const chatDialog = document.getElementById('chatDialog');
const chatForm = document.getElementById('chatForm');
const chatInput = document.getElementById('chatInput');
const chatHistory = document.getElementById('chatHistory');
const chatModelName = document.getElementById('chatModelName');
const keyDialog = document.getElementById('keyDialog');
const keyForm = document.getElementById('createKeyForm');
const ipDialog = document.getElementById('ipDialog');
const ipForm = document.getElementById('addIpForm');
const settingsDialog = document.getElementById('settingsDialog');
const settingsForm = document.getElementById('editSettingsForm');

// API call wrapper
async function apiCall(url, method = 'GET', body = null) {
    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };
    if (body) options.body = JSON.stringify(body);
    try {
        const response = await fetch(url, options);
        if (response.status === 401) {
            logout();
            return null;
        }
        if (!response.ok) {
            const errorText = await response.text();
            if (response.status === 429) {
                alert('Quota or rate limit exceeded. Please try again later.');
            }
            throw new Error(errorText || `API Error: ${response.status}`);
        }
        return response.status === 204 ? null : response.json();
    } catch (error) {
        console.error(`API call failed for ${method} ${url}:`, error);
        alert(`Error: ${error.message}`);
        throw error;
    }
}

// Tab management
function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.tab-btn').forEach(el => {
        el.className = 'tab-btn px-4 py-2 rounded-md text-sm font-medium text-gray-500 hover:text-gray-700';
    });
    document.getElementById(`content-${tabName}`).classList.remove('hidden');
    document.getElementById(`tab-${tabName}`).className = 'tab-btn px-4 py-2 rounded-md text-sm font-medium bg-white shadow-sm text-blue-600';

    // Load data for active tab
    if (tabName === 'dashboard') loadDashboard();
    else if (tabName === 'models') loadModels();
    else if (tabName === 'keys') loadKeys();
    else if (tabName === 'logs') loadLogs();
    else if (tabName === 'ips') loadIPs();
    else if (tabName === 'settings') loadSettings();
}

// Auth
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('email');
    window.location.href = '/web/login.html';
}

// Dashboard
async function loadDashboard() {
    try {
        const data = await apiCall('/admin/dashboard');
        document.getElementById('activeKeys').textContent = data.active_keys || 0;
        document.getElementById('requestsToday').textContent = data.requests_today || 0;
        document.getElementById('totalUsers').textContent = data.total_users || 0;
        document.getElementById('avgLatency').textContent = Math.round(data.avg_latency) + 'ms';

        const topList = document.getElementById('topEndpoints');
        topList.innerHTML = data.top_endpoints?.map(ep => `<li class="flex justify-between"><span>${ep.endpoint}</span><span class="font-medium">${ep.count}</span></li>`).join('') || '<li>No data</li>';

        // Bar chart for latency (mock yesterday for simplicity)
        const ctx = document.getElementById('latencyChart').getContext('2d');
        if (latencyChart) latencyChart.destroy();
        latencyChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Today', 'Yesterday'],
                datasets: [{ label: 'Avg Latency (ms)', data: [data.avg_latency, 150], backgroundColor: 'rgba(59, 130, 246, 0.5)' }]
            },
            options: { scales: { y: { beginAtZero: true } }, responsive: true }
        });
    } catch (e) {
        document.getElementById('activeKeys').textContent = 'Error';
    }
}

// API Keys
async function showCreateKeyDialog() {
    if (models.length === 0) {
        models = await apiCall('/admin/models') || [];
    }
    const select = document.getElementById('keyModelId');
    select.innerHTML = '<option value="">Select Model</option>' + models.map(m => `<option value="${m.id}">${m.name}</option>`).join('');
    keyForm.reset();
    keyDialog.classList.remove('hidden');
}

function hideCreateKeyDialog() {
    keyDialog.classList.add('hidden');
    keyForm.reset();
}

async function loadKeys() {
    const keys = await apiCall('/admin/keys');
    const container = document.getElementById('keysList');
    if (!keys || keys.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No API keys found. Create one after setting up models.</p>';
        return;
    }
    container.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Model</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Label / Owner</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Limits</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Expires</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                ${keys.map(key => `
                    <tr>
                        <td class="px-6 py-4"><code class="text-sm bg-gray-100 p-1 rounded break-all">${key.key}</code></td>
                        <td class="px-6 py-4 text-sm font-medium text-gray-800">${key.model_name}</td>
                        <td class="px-6 py-4 text-sm text-gray-600">${key.label || 'N/A'} / ${key.owner || 'N/A'}</td>
                        <td class="px-6 py-4 text-sm text-gray-600 text-right">${key.daily_limit} daily / ${key.token_limit} tokens</td>
                        <td class="px-6 py-4 text-sm text-gray-600 text-right">${key.expires_at || 'Never'}</td>
                        <td class="px-6 py-4 text-right">
                            <button onclick="deleteKey(${key.id})" class="text-red-600 hover:text-red-800 text-sm">Delete</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

async function createKey(e) {
    e.preventDefault();
    const keyData = {
        label: document.getElementById('keyLabel').value,
        owner: document.getElementById('keyOwner').value,
        model_id: parseInt(document.getElementById('keyModelId').value),
        daily_limit: parseInt(document.getElementById('keyDailyLimit').value) || 0,
        token_limit: parseInt(document.getElementById('keyTokenLimit').value) || 0
    };
    const expiresAt = document.getElementById('keyExpiresAt').value;
    if (expiresAt) keyData.expires_at = expiresAt + 'T00:00:00Z';
    if (!keyData.model_id) {
        alert("Please select a model.");
        return;
    }
    const newKey = await apiCall('/admin/keys', 'POST', keyData);
    if (newKey) {
        alert(`New key created: ${newKey.key}`);
    }
    hideCreateKeyDialog();
    loadKeys();
}

async function deleteKey(id) {
    if (confirm('Are you sure you want to delete this API key?')) {
        await apiCall(`/admin/keys/${id}`, 'DELETE');
        loadKeys();
    }
}

// Models
function showModelDialog() {
    document.getElementById('testResult').innerHTML = '';
    modelForm.reset();
    modelDialog.classList.remove('hidden');
}

function hideModelDialog() {
    modelForm.reset();
    modelDialog.classList.add('hidden');
}

async function loadModels() {
    models = await apiCall('/admin/models') || [];
    const container = document.getElementById('modelsList');
    if (models.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No models found. Add one to get started with API keys.</p>';
        return;
    }
    container.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Backend / Model</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Params</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                ${models.map(m => `
                    <tr>
                        <td class="px-6 py-4 font-medium text-gray-900">${m.name}</td>
                        <td class="px-6 py-4 text-sm text-gray-600">${m.backend} / ${m.model_name}</td>
                        <td class="px-6 py-4 text-sm text-gray-600">Temp: ${m.temperature}, Max: ${m.max_tokens}</td>
                        <td class="px-6 py-4 text-right text-sm font-medium space-x-4">
                            <button onclick="openChatDialog(${m.id}, '${m.name}')" class="text-green-600 hover:text-green-800">Chat</button>
                            <button onclick="deleteModel(${m.id})" class="text-red-600 hover:text-red-800">Delete</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

async function createModel(e) {
    e.preventDefault();
    const formData = new FormData(modelForm);
    const modelData = {
        name: formData.get('name'),
        backend: formData.get('backend'),
        url: formData.get('url'),
        model_name: formData.get('model_name'),
        temperature: parseFloat(formData.get('temperature')) || 0.7,
        max_tokens: parseInt(formData.get('max_tokens')) || 512,
    };
    await apiCall('/admin/models', 'POST', modelData);
    hideModelDialog();
    loadModels();
}

async function testConnection() {
    const btn = document.getElementById('testConnectionBtn');
    const resultDiv = document.getElementById('testResult');
    const testData = { url: modelForm.elements.url.value };
    btn.textContent = 'Testing...';
    btn.disabled = true;
    resultDiv.innerHTML = '';
    try {
        const result = await apiCall('/admin/models/test', 'POST', testData);
        resultDiv.className = 'text-sm p-2 rounded-md bg-green-100 text-green-800';
        resultDiv.textContent = result.ok ? `Success! Status: ${result.status}` : `Failed! ${result.error}`;
    } catch (e) {
        resultDiv.className = 'text-sm p-2 rounded-md bg-red-100 text-red-800';
        resultDiv.textContent = `Error: ${e.message}`;
    } finally {
        btn.textContent = 'Test Connection';
        btn.disabled = false;
    }
}

async function deleteModel(id) {
    if (confirm('This will also delete any linked API keys. Continue?')) {
        await apiCall(`/admin/models/${id}`, 'DELETE');
        loadModels();
    }
}

// Chat
function openChatDialog(modelId, modelName) {
    currentChatModelId = modelId;
    chatMessages = [];
    chatModelName.textContent = `Chat with ${modelName}`;
    chatHistory.innerHTML = '<div class="chat-bubble llm">Hi! How can I help you today?</div>';
    chatDialog.classList.remove('hidden');
    chatInput.focus();
}

function closeChatDialog() {
    chatDialog.classList.add('hidden');
    currentChatModelId = null;
    chatMessages = [];
}

chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const prompt = chatInput.value.trim();
    if (!prompt) return;
    chatMessages.push({ role: 'user', content: prompt });
    chatHistory.innerHTML += `<div class="chat-bubble user">${prompt}</div>`;
    chatInput.value = '';
    chatHistory.scrollTop = chatHistory.scrollHeight;

    const typingIndicator = document.createElement('div');
    typingIndicator.className = 'chat-bubble llm animate-pulse';
    typingIndicator.textContent = '...';
    chatHistory.appendChild(typingIndicator);
    chatHistory.scrollTop = chatHistory.scrollHeight;

    try {
        const response = await apiCall(`/admin/models/${currentChatModelId}/chat`, 'POST', { prompt });
        typingIndicator.remove();
        chatMessages.push({ role: 'llm', content: response.output });
        chatHistory.innerHTML += `<div class="chat-bubble llm">${response.output}</div>`;
    } catch (e) {
        typingIndicator.textContent = `Error: ${e.message}`;
    }
    chatHistory.scrollTop = chatHistory.scrollHeight;
});

chatDialog.addEventListener('click', (event) => {
    if (event.target === chatDialog) closeChatDialog();
});

// IP Access
function showCreateIPDialog() {
    ipForm.reset();
    ipDialog.classList.remove('hidden');
}

function hideIPDialog() {
    ipForm.reset();
    ipDialog.classList.add('hidden');
}

async function loadIPs() {
    const ips = await apiCall('/admin/ips');
    const container = document.getElementById('ipsList');
    if (!ips || ips.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No IP restrictions configured. Access is open.</p>';
        return;
    }
    container.innerHTML = `
        <div class="space-y-3">
            ${ips.map(ip => `
                <div class="flex items-center justify-between p-3 border rounded-lg ${ip.is_active ? 'bg-green-50' : 'bg-gray-50'}">
                    <div>
                        <span class="font-mono text-sm">${ip.ip_address}</span>
                        <p class="text-xs text-gray-500">${ip.label || 'No description'}</p>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${ip.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}">${ip.is_active ? 'Active' : 'Inactive'}</span>
                        <button onclick="toggleIP(${ip.id})" class="text-sm text-blue-600 hover:text-blue-800">${ip.is_active ? 'Disable' : 'Enable'}</button>
                        <button onclick="deleteIP(${ip.id}, '${ip.ip_address}')" class="text-sm text-red-600 hover:text-red-800">Delete</button>
                    </div>
                </div>
            `).join('')}
        </div>`;
}

async function createIP(e) {
    e.preventDefault();
    const formData = new FormData(ipForm);
    const ipData = {
        ip_address: formData.get('ip_address'),
        label: formData.get('label')
    };
    await apiCall('/admin/ips', 'POST', ipData);
    hideIPDialog();
    loadIPs();
}

async function toggleIP(id) {
    await apiCall(`/admin/ips/${id}/toggle`, 'PUT');
    loadIPs();
}

async function deleteIP(id, ipAddress) {
    if (confirm(`Delete IP restriction for "${ipAddress}"?`)) {
        await apiCall(`/admin/ips/${id}`, 'DELETE');
        loadIPs();
    }
}

// Settings
function showSettingsDialog() {
    settingsForm.reset();
    const settings = document.getElementById('settingsTable').dataset.settings;
    if (settings) {
        const { company_name, logo_url, admin_email, license_key } = JSON.parse(settings);
        document.getElementById('company_name').value = company_name || '';
        document.getElementById('logo_url').value = logo_url || '';
        document.getElementById('admin_email').value = admin_email || '';
        document.getElementById('license_key').value = license_key || '';
    }
    settingsDialog.classList.remove('hidden');
}

function hideSettingsDialog() {
    settingsDialog.classList.add('hidden');
}

async function loadSettings() {
    const settings = await apiCall('/admin/settings');
    const container = document.getElementById('settingsTable');
    if (!settings) {
        container.innerHTML = '<p class="text-gray-500">Error loading settings.</p>';
        return;
    }
    container.dataset.settings = JSON.stringify(settings);
    const logoImg = settings.logo_url ? `<img src="${settings.logo_url}" alt="Logo" class="h-8 w-auto">` : 'No Logo';
    container.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Setting</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Value</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <tr><td class="px-6 py-4 text-sm font-medium text-gray-900">Company Name</td><td class="px-6 py-4 text-sm text-gray-600">${settings.company_name || 'N/A'}</td></tr>
                <tr><td class="px-6 py-4 text-sm font-medium text-gray-900">Logo</td><td class="px-6 py-4 text-sm text-gray-600">${logoImg}</td></tr>
                <tr><td class="px-6 py-4 text-sm font-medium text-gray-900">Admin Email</td><td class="px-6 py-4 text-sm text-gray-600">${settings.admin_email || 'N/A'}</td></tr>
                <tr><td class="px-6 py-4 text-sm font-medium text-gray-900">License Key</td><td class="px-6 py-4 text-sm text-gray-600">${settings.license_key ? 'Active' : 'Free Mode'}</td></tr>
            </tbody>
        </table>`;
}

async function saveSettings(e) {
    e.preventDefault();
    const settingsData = {
        company_name: document.getElementById('company_name').value,
        logo_url: document.getElementById('logo_url').value,
        admin_email: document.getElementById('admin_email').value,
        license_key: document.getElementById('license_key').value
    };
    await apiCall('/admin/settings', 'PUT', settingsData);
    alert('Settings saved successfully!');
    hideSettingsDialog();
    loadSettings();
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Set up user display
    document.getElementById('userEmail').textContent = email;
    document.getElementById('userAvatar').textContent = email.charAt(0).toUpperCase();

    // Attach tab listeners
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => showTab(btn.id.replace('tab-', '')));
    });

    // Form submit listeners
    modelForm.addEventListener('submit', createModel);
    keyForm.addEventListener('submit', createKey);
    ipForm.addEventListener('submit', createIP);
    settingsForm.addEventListener('submit', saveSettings);

    // Start with dashboard
    showTab('dashboard');
});