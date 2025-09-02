const token = localStorage.getItem('token');
if (!token) {
    window.location.href = '/web/login.html';
}

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
    
    const response = await fetch(url, options);
    
    if (response.status === 401) {
        localStorage.removeItem('token');
        window.location.href = '/web/login.html';
        return;
    }
    
    if (response.ok && response.status !== 204) {
        return await response.json();
    }
    
    return response.ok;
}

function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('[id^="tab-"]').forEach(el => {
        el.className = 'px-4 py-2 rounded-md text-sm font-medium text-gray-500 hover:text-gray-700';
    });
    
    document.getElementById(`content-${tabName}`).classList.remove('hidden');
    document.getElementById(`tab-${tabName}`).className = 'px-4 py-2 rounded-md text-sm font-medium bg-white shadow-sm text-blue-600';
    
    if (tabName === 'keys') loadKeys();
    else if (tabName === 'model') loadModel();
    else if (tabName === 'logs') loadLogs();
    else if (tabName === 'settings') loadSettings();
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = '/web/login.html';
}

async function loadKeys() {
    const keys = await apiCall('/admin/keys');
    const container = document.getElementById('keysList');
    
    if (!keys || keys.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No API keys found.</p>';
        return;
    }
    
    container.innerHTML = keys.map(key => `
        <div class="flex items-center justify-between p-4 border rounded-lg">
            <div class="flex-1">
                <div class="font-mono text-sm bg-gray-100 px-2 py-1 rounded">${key.key}</div>
                <div class="text-sm text-gray-600 mt-1">
                    ${key.label || 'No label'} • ${key.owner || 'No owner'} • Created: ${new Date(key.created_at).toLocaleDateString()}
                </div>
            </div>
            <button onclick="deleteKey(${key.id})" class="text-red-600 hover:text-red-800 ml-4">Delete</button>
        </div>
    `).join('');
}

function showCreateKeyForm() {
    document.getElementById('createKeyForm').classList.remove('hidden');
}

function hideCreateKeyForm() {
    document.getElementById('createKeyForm').classList.add('hidden');
    document.getElementById('keyLabel').value = '';
    document.getElementById('keyOwner').value = '';
}

async function createKey() {
    const label = document.getElementById('keyLabel').value;
    const owner = document.getElementById('keyOwner').value;
    
    const result = await apiCall('/admin/keys', 'POST', { label, owner });
    
    if (result) {
        hideCreateKeyForm();
        loadKeys();
    }
}

async function deleteKey(id) {
    if (confirm('Delete this API key?')) {
        await apiCall(`/admin/keys/${id}`, 'DELETE');
        loadKeys();
    }
}

async function loadModel() {
    const config = await apiCall('/admin/model');
    
    if (config) {
        document.getElementById('backend').value = config.backend;
        document.getElementById('url').value = config.url;
        document.getElementById('model_name').value = config.model_name;
        document.getElementById('temperature').value = config.temperature;
        document.getElementById('max_tokens').value = config.max_tokens;
    }
}

document.getElementById('modelForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const config = {
        backend: document.getElementById('backend').value,
        url: document.getElementById('url').value,
        model_name: document.getElementById('model_name').value,
        temperature: parseFloat(document.getElementById('temperature').value),
        max_tokens: parseInt(document.getElementById('max_tokens').value)
    };
    
    const success = await apiCall('/admin/model', 'PUT', config);
    
    if (success) {
        alert('Model configuration saved!');
    }
});

async function testModel() {
    const result = await apiCall('/admin/model/test', 'POST');
    const resultDiv = document.getElementById('testResult');
    
    if (result) {
        resultDiv.innerHTML = result.ok ? 
            '<div class="text-green-600">✅ Connection successful</div>' :
            `<div class="text-red-600">❌ Connection failed: ${result.error || result.status}</div>`;
    }
}

async function loadLogs() {
    const logs = await apiCall('/admin/logs');
    const container = document.getElementById('logsList');
    
    if (!logs || logs.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No usage logs found.</p>';
        return;
    }
    
    container.innerHTML = logs.map(log => `
        <div class="flex items-center justify-between py-2 border-b border-gray-100">
            <div class="flex-1">
                <span class="text-sm text-gray-900">${log.endpoint}</span>
                <span class="text-xs text-gray-500 ml-2">${log.tokens} tokens • ${log.latency_ms}ms • ${new Date(log.ts).toLocaleString()}</span>
            </div>
            <div class="text-xs text-gray-500">API Key: ${log.api_key_id}</div>
        </div>
    `).join('');
}

async function loadSettings() {
    try {
        const settings = await apiCall('/admin/settings');
        
        if (settings) {
            document.getElementById('company_name').value = settings.company_name || '';
            document.getElementById('admin_email').value = settings.admin_email || '';
            document.getElementById('ip_allowlist').value = settings.ip_allowlist || '';
            document.getElementById('license_key').value = settings.license_key || '';
        }
    } catch (error) {
        showDialog('Failed to load settings: ' + error.message, false);
    }
}

document.getElementById('settingsForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const settings = {
        company_name: document.getElementById('company_name').value,
        admin_email: document.getElementById('admin_email').value,
        ip_allowlist: document.getElementById('ip_allowlist').value,
        license_key: document.getElementById('license_key').value,
        https_enabled: false
    };
    
    try {
        const success = await apiCall('/admin/settings', 'PUT', settings);
        
        if (success) {
            showDialog('Settings saved successfully!');
        }
    } catch (error) {
        showDialog('Failed to save settings: ' + error.message, false);
    }
});

showTab('keys');

async function loadModels() {
    try {
        const models = await apiCall('/admin/models');
        const container = document.getElementById('modelsList');
        
        if (!models || models.length === 0) {
            container.innerHTML = '<p class="text-gray-500">No models configured.</p>';
            return;
        }
        
        container.innerHTML = models.map(model => `
            <div class="flex items-center justify-between p-4 border rounded-lg ${model.is_active ? 'border-green-500 bg-green-50' : ''}">
                <div class="flex-1">
                    <div class="font-semibold">${model.name}</div>
                    <div class="text-sm text-gray-600">
                        ${model.backend} • ${model.model_name} • ${model.url}
                        ${model.is_active ? '<span class="text-green-600 ml-2">● Active</span>' : ''}
                    </div>
                </div>
                <div class="flex space-x-2">
                    ${!model.is_active ? `<button onclick="activateModel(${model.id})" class="bg-blue-600 text-white px-3 py-1 rounded text-sm">Activate</button>` : ''}
                    <button onclick="deleteModel(${model.id})" class="text-red-600 hover:text-red-800 text-sm">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        showDialog('Failed to load models: ' + error.message, false);
    }
}

async function createModel() {
    const modelData = {
        name: document.getElementById('newModelName').value,
        backend: document.getElementById('newModelBackend').value,
        url: document.getElementById('newModelUrl').value,
        model_name: document.getElementById('newModelModelName').value,
        temperature: parseFloat(document.getElementById('newModelTemp').value),
        max_tokens: parseInt(document.getElementById('newModelMaxTokens').value),
        is_active: document.getElementById('newModelActive').checked
    };
    
    try {
        await apiCall('/admin/models', 'POST', modelData);
        showDialog('Model configuration created successfully!');
        hideCreateModelForm();
        loadModels();
    } catch (error) {
        showDialog('Failed to create model: ' + error.message, false);
    }
}

async function activateModel(id) {
    try {
        await apiCall(`/admin/models/${id}/activate`, 'PUT');
        showDialog('Model activated successfully!');
        loadModels();
    } catch (error) {
        showDialog('Failed to activate model: ' + error.message, false);
    }
}

async function deleteModel(id) {
    if (confirm('Delete this model configuration?')) {
        try {
            await apiCall(`/admin/models/${id}`, 'DELETE');
            showDialog('Model deleted successfully!');
            loadModels();
        } catch (error) {
            showDialog('Failed to delete model: ' + error.message, false);
        }
    }
}

async function loadIPs() {
    try {
        const ips = await apiCall('/admin/ips');
        const container = document.getElementById('ipsList');
        
        if (!ips || ips.length === 0) {
            container.innerHTML = '<p class="text-gray-500">No IP restrictions configured. All IPs are allowed.</p>';
            return;
        }
        
        container.innerHTML = ips.map(ip => `
            <div class="flex items-center justify-between p-3 border rounded-lg ${ip.is_active ? 'border-green-500' : 'border-gray-300 opacity-50'}">
                <div class="flex-1">
                    <div class="font-mono text-sm">${ip.ip_address}</div>
                    <div class="text-xs text-gray-600">${ip.label || 'No description'}</div>
                </div>
                <div class="flex space-x-2">
                    <button onclick="toggleIP(${ip.id})" class="text-blue-600 hover:text-blue-800 text-sm">
                        ${ip.is_active ? 'Disable' : 'Enable'}
                    </button>
                    <button onclick="deleteIP(${ip.id})" class="text-red-600 hover:text-red-800 text-sm">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        showDialog('Failed to load IP allowlist: ' + error.message, false);
    }
}

async function createIP() {
    const ipData = {
        ip_address: document.getElementById('newIPAddress').value,
        label: document.getElementById('newIPLabel').value
    };
    
    try {
        await apiCall('/admin/ips', 'POST', ipData);
        showDialog('IP address added successfully!');
        hideCreateIPForm();
        loadIPs();
    } catch (error) {
        showDialog('Failed to add IP: ' + error.message, false);
    }
}

async function toggleIP(id) {
    try {
        await apiCall(`/admin/ips/${id}/toggle`, 'PUT');
        showDialog('IP status updated!');
        loadIPs();
    } catch (error) {
        showDialog('Failed to update IP status: ' + error.message, false);
    }
}

async function deleteIP(id) {
    if (confirm('Delete this IP address?')) {
        try {
            await apiCall(`/admin/ips/${id}`, 'DELETE');
            showDialog('IP address deleted successfully!');
            loadIPs();
        } catch (error) {
            showDialog('Failed to delete IP: ' + error.message, false);
        }
    }
}

function showCreateModelForm() {
    document.getElementById('createModelForm').classList.remove('hidden');
}

function hideCreateModelForm() {
    document.getElementById('createModelForm').classList.add('hidden');
    // Clear form
    document.getElementById('newModelName').value = '';
    document.getElementById('newModelUrl').value = '';
    document.getElementById('newModelModelName').value = '';
    document.getElementById('newModelTemp').value = '0.7';
    document.getElementById('newModelMaxTokens').value = '512';
    document.getElementById('newModelActive').checked = false;
}

function showCreateIPForm() {
    document.getElementById('createIPForm').classList.remove('hidden');
}

function hideCreateIPForm() {
    document.getElementById('createIPForm').classList.add('hidden');
    document.getElementById('newIPAddress').value = '';
    document.getElementById('newIPLabel').value = '';
}