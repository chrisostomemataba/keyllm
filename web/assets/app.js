const token = localStorage.getItem('token');
if (!token) {
    window.location.href = '/web/login.html';
}

// --- API Abstraction ---
async function apiCall(url, method = 'GET', body = null) {
    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };
    if (body) {
        options.body = JSON.stringify(body);
    }
    try {
        const response = await fetch(url, options);
        if (response.status === 401) {
            logout();
            return;
        }
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `API Error: ${response.status}`);
        }
        return response.status === 204 ? null : response.json();
    } catch (error) {
        console.error(`API call failed for ${method} ${url}:`, error);
        alert(`An error occurred: ${error.message}`);
        throw error;
    }
}

// --- Tab Management ---
function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('[id^="tab-"]').forEach(el => {
        el.className = 'px-4 py-2 rounded-md text-sm font-medium text-gray-500 hover:text-gray-700';
    });
    document.getElementById(`content-${tabName}`).classList.remove('hidden');
    document.getElementById(`tab-${tabName}`).className = 'px-4 py-2 rounded-md text-sm font-medium bg-white shadow-sm text-blue-600';

    if (tabName === 'keys') loadKeys();
    else if (tabName === 'models') loadModels();
    else if (tabName === 'ips') loadIPs();
    else if (tabName === 'logs') loadLogs();
    else if (tabName === 'settings') loadSettings();
}

// --- Auth ---
function logout() {
    localStorage.removeItem('token');
    window.location.href = '/web/login.html';
}

// --- API Keys Section ---
async function showCreateKeyForm() {
    // Fetch models and populate the dropdown
    const models = await apiCall('/admin/models');
    const select = document.getElementById('keyModelId');
    select.innerHTML = '<option value="">-- Select a Model --</option>'; // Default option
    if (models) {
        models.forEach(model => {
            select.innerHTML += `<option value="${model.id}">${model.name}</option>`;
        });
    }
    document.getElementById('createKeyForm').classList.remove('hidden');
}

function hideCreateKeyForm() { document.getElementById('createKeyForm').classList.add('hidden'); }

async function loadKeys() {
    const keys = await apiCall('/admin/keys');
    const container = document.getElementById('keysList');
    if (!keys || keys.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No API keys created yet.</p>';
        return;
    }
    container.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Linked Model</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Label / Owner</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                ${keys.map(key => `
                    <tr>
                        <td class="px-6 py-4"><code class="text-sm bg-gray-100 p-1 rounded">${key.key}</code></td>
                        <td class="px-6 py-4 text-sm font-medium text-gray-800">${key.model_name}</td>
                        <td class="px-6 py-4 text-sm text-gray-600">${key.label || 'N/A'} / ${key.owner || 'N/A'}</td>
                        <td class="px-6 py-4 text-right">
                            <button onclick="deleteKey(${key.id})" class="text-red-600 hover:text-red-800">Delete</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

async function createKey() {
    const keyData = {
        label: document.getElementById('keyLabel').value,
        owner: document.getElementById('keyOwner').value,
        model_id: parseInt(document.getElementById('keyModelId').value)
    };
    if (!keyData.model_id) {
        alert("Please select a model to link to the API key.");
        return;
    }
    await apiCall('/admin/keys', 'POST', keyData);
    hideCreateKeyForm();
    loadKeys();
}

async function deleteKey(id) {
    if (confirm('Are you sure you want to delete this key?')) {
        await apiCall(`/admin/keys/${id}`, 'DELETE');
        loadKeys();
    }
}

// --- Model Config Section ---
const modelDialog = document.getElementById('modelDialog');
const modelForm = document.getElementById('addModelForm');
function showModelDialog() {
    document.getElementById('testResult').innerHTML = ''; // Clear previous test results
    modelDialog.classList.remove('hidden');
}
function hideModelDialog() { modelForm.reset(); modelDialog.classList.add('hidden'); }

async function loadModels() {
    const models = await apiCall('/admin/models');
    const container = document.getElementById('modelsList');
    if (!models || models.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No models found. Click "Add Model" to create one.</p>';
        return;
    }
    container.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Backend / Model</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                ${models.map(m => `
                    <tr>
                        <td class="px-6 py-4 font-medium text-gray-900">${m.name}</td>
                        <td class="px-6 py-4 text-sm text-gray-600">${m.backend} / ${m.model_name}</td>
                        <td class="px-6 py-4 text-right text-sm font-medium space-x-4">
                            <button onclick="openChatDialog(${m.id}, '${m.name}')" class="text-green-600 hover:text-green-800">Chat</button>
                            <button onclick="deleteModel(${m.id})" class="text-red-600 hover:text-red-800">Delete</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

async function createModel() {
    const formData = new FormData(modelForm);
    const modelData = {
        name: formData.get('name'),
        backend: formData.get('backend'),
        url: formData.get('url'),
        model_name: formData.get('model_name'),
        temperature: parseFloat(formData.get('temperature')),
        max_tokens: parseInt(formData.get('max_tokens')),
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
        if (result.ok) {
            resultDiv.className = 'text-sm p-2 rounded-md bg-green-100 text-green-800';
            resultDiv.textContent = `Success! Status: ${result.status}`;
        } else {
            resultDiv.className = 'text-sm p-2 rounded-md bg-red-100 text-red-800';
            resultDiv.textContent = `Failed! ${result.error || result.status}`;
        }
    } catch (e) {
        resultDiv.className = 'text-sm p-2 rounded-md bg-red-100 text-red-800';
        resultDiv.textContent = `Error: ${e.message}`;
    } finally {
        btn.textContent = 'Test Connection';
        btn.disabled = false;
    }
}

async function deleteModel(id) {
    if (confirm('This will also delete any API keys linked to this model. Continue?')) {
        await apiCall(`/admin/models/${id}`, 'DELETE');
        loadModels();
    }
}

// --- Chat Dialog Logic (NEW) ---
const chatDialog = document.getElementById('chatDialog');
const chatForm = document.getElementById('chatForm');
const chatInput = document.getElementById('chatInput');
const chatHistory = document.getElementById('chatHistory');
const chatModelName = document.getElementById('chatModelName');
let currentChatModelId = null;
let chatMessages = [];

function openChatDialog(modelId, modelName) {
    currentChatModelId = modelId;
    chatMessages = []; // Clear history for new session
    chatModelName.textContent = `Chat with ${modelName}`;
    chatHistory.innerHTML = '<div class="chat-bubble llm">Hi! How can I help you today?</div>';
    chatDialog.classList.remove('hidden');
    chatInput.focus();
}

function closeChatDialog() {
    chatDialog.classList.add('hidden');
    currentChatModelId = null;
}

chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const prompt = chatInput.value.trim();
    if (!prompt) return;

    // Add user message to UI
    chatHistory.innerHTML += `<div class="chat-bubble user">${prompt}</div>`;
    chatInput.value = '';
    chatHistory.scrollTop = chatHistory.scrollHeight;

    // Show typing indicator
    const typingIndicator = document.createElement('div');
    typingIndicator.className = 'chat-bubble llm animate-pulse';
    typingIndicator.textContent = '...';
    chatHistory.appendChild(typingIndicator);
    chatHistory.scrollTop = chatHistory.scrollHeight;

    try {
        const response = await apiCall(`/admin/models/${currentChatModelId}/chat`, 'POST', { prompt });
        typingIndicator.remove(); // Remove indicator
        // Add LLM response to UI
        chatHistory.innerHTML += `<div class="chat-bubble llm">${response.output}</div>`;
    } catch (e) {
        typingIndicator.textContent = `Error: ${e.message}`;
    }
    chatHistory.scrollTop = chatHistory.scrollHeight;
});
// Add a click listener to the backdrop to close the chat
chatDialog.addEventListener('click', (event) => {
    if (event.target === chatDialog) {
        closeChatDialog();
    }
});

// --- IP Access Section ---
const ipDialog = document.getElementById('ipDialog');
const ipForm = document.getElementById('addIpForm');
function showCreateIPDialog() { ipDialog.classList.remove('hidden'); }
function hideIPDialog() { ipForm.reset(); ipDialog.classList.add('hidden'); }

async function loadIPs() {
    const ips = await apiCall('/admin/ips');
    const container = document.getElementById('ipsList');
    if (!ips || ips.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No IP restrictions configured. Access is currently open.</p>';
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
                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${ip.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}">${ip.is_active ? 'Enabled' : 'Disabled'}</span>
                    <button onclick="toggleIP(${ip.id})" class="text-sm text-blue-600 hover:text-blue-800">${ip.is_active ? 'Disable' : 'Enable'}</button>
                    <button onclick="deleteIP(${ip.id}, '${ip.ip_address}')" class="text-sm text-red-600 hover:text-red-800">Delete</button>
                </div>
            </div>
        `).join('')}
        </div>
    `;
}

async function createIP() {
    try {
        const formData = new FormData(ipForm);
        const ipData = {
            ip_address: formData.get('ip_address'),
            label: formData.get('label')
        };
        await apiCall('/admin/ips', 'POST', ipData);
        hideIPDialog();
        loadIPs();
    } catch (error) {
        console.error("Failed to create IP restriction:", error);
    }
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

// --- Usage Logs Section ---
async function loadLogs() {
    const logs = await apiCall('/admin/logs?limit=100');
    const container = document.getElementById('logsList');
    if (!logs || logs.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No usage logs found.</p>';
        return;
    }
    container.innerHTML = `
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Endpoint</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key ID</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                ${logs.map(log => `
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">${new Date(log.ts).toLocaleString()}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-800 font-medium">${log.endpoint}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">${log.tokens} tokens · ${log.latency_ms}ms</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">${log.api_key_id}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

// --- Settings Section ---
async function loadSettings() {
    const settings = await apiCall('/admin/settings');
    if (settings) {
        document.getElementById('company_name').value = settings.company_name || '';
        document.getElementById('admin_email').value = settings.admin_email || '';
        document.getElementById('license_key').value = settings.license_key || '';
    }
}

async function saveSettings() {
    const settingsData = {
        company_name: document.getElementById('company_name').value,
        admin_email: document.getElementById('admin_email').value,
        license_key: document.getElementById('license_key').value
    };
    await apiCall('/admin/settings', 'PUT', settingsData);
    alert('Settings saved successfully!');
}

// --- Initial Load ---
document.addEventListener('DOMContentLoaded', () => {
    showTab('keys');
});