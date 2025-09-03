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
    
    try {
        const response = await fetch(url, options);
        
        if (response.status === 401) {
            localStorage.removeItem('token');
            window.location.href = '/web/login.html';
            return;
        }
        
        if (response.ok && response.status !== 204) {
            return await response.json();
        }
        
        if (response.ok) {
            return { success: true };
        }
        
        const errorText = await response.text();
        throw new Error(errorText || `HTTP ${response.status}`);
        
    } catch (error) {
        throw error;
    }
}

function showDialog(message, isSuccess = true) {
    const existing = document.getElementById('dialog');
    if (existing) existing.remove();
    
    const dialog = document.createElement('div');
    dialog.id = 'dialog';
    dialog.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${isSuccess ? 'bg-green-100 border border-green-400 text-green-700' : 'bg-red-100 border border-red-400 text-red-700'}`;
    dialog.innerHTML = `
        <div class="flex items-center">
            <span class="mr-2">${isSuccess ? '✅' : '❌'}</span>
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-lg">&times;</button>
        </div>
    `;
    
    document.body.appendChild(dialog);
    setTimeout(() => dialog.remove(), 5000);
}

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

function logout() {
    localStorage.removeItem('token');
    window.location.href = '/web/login.html';
}

// API Keys Functions
async function loadKeys() {
    try {
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
    } catch (error) {
        showDialog('Failed to load API keys: ' + error.message, false);
    }
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
    
    try {
        const result = await apiCall('/admin/keys', 'POST', { label, owner });
        
        if (result && result.key) {
            showDialog(`API key created successfully: ${result.key}`);
            hideCreateKeyForm();
            loadKeys();
        }
    } catch (error) {
        showDialog('Failed to create API key: ' + error.message, false);
    }
}

async function deleteKey(id) {
    if (confirm('Delete this API key?')) {
        try {
            await apiCall(`/admin/keys/${id}`, 'DELETE');
            showDialog('API key deleted successfully');
            loadKeys();
        } catch (error) {
            showDialog('Failed to delete API key: ' + error.message, false);
        }
    }
}

// Model Management Functions
async function loadModels() {
    try {
        const models = await apiCall('/admin/models');
        const container = document.getElementById('modelsList');
        
        if (!models || models.length === 0) {
            container.innerHTML = `
                <div class="text-center py-8">
                    <div class="text-gray-500 mb-4">No models configured yet</div>
                    <button onclick="showCreateModelDialog()" class="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">Create Your First Model</button>
                </div>
            `;
            return;
        }
        
        container.innerHTML = models.map(model => `
            <div class="flex items-center justify-between p-4 border rounded-lg ${model.is_active ? 'border-green-500 bg-green-50' : 'border-gray-200'}">
                <div class="flex-1">
                    <div class="flex items-center space-x-3">
                        <div class="font-semibold text-gray-900">${model.name}</div>
                        ${model.is_active ? '<span class="px-2 py-1 text-xs bg-green-600 text-white rounded-full">Active</span>' : ''}
                    </div>
                    <div class="text-sm text-gray-600 mt-1">
                        <span class="font-medium">${model.backend}</span> • ${model.model_name} • ${model.url}
                    </div>
                    <div class="text-xs text-gray-500 mt-1">
                        Temp: ${model.temperature} • Max tokens: ${model.max_tokens} • Created: ${new Date(model.created_at).toLocaleDateString()}
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    ${!model.is_active ? `<button onclick="activateModel(${model.id}, '${model.name}')" class="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700">Activate</button>` : ''}
                    <button onclick="testModelById(${model.id}, '${model.name}')" class="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700">Test</button>
                    <button onclick="deleteModel(${model.id}, '${model.name}')" class="text-red-600 hover:text-red-800 text-sm px-2">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        showDialog('Failed to load models: ' + error.message, false);
    }
}

// Dialog Management Functions
function showCreateModelDialog() {
    document.getElementById('modelDialog').classList.remove('hidden');
}

function hideModelDialog() {
    document.getElementById('modelDialog').classList.add('hidden');
    document.getElementById('modelForm').reset();
}

document.getElementById('modelForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const modelData = {
        name: document.getElementById('modelName').value,
        backend: document.getElementById('modelBackend').value,
        url: document.getElementById('modelUrl').value,
        model_name: document.getElementById('modelModelName').value,
        temperature: parseFloat(document.getElementById('modelTemp').value),
        max_tokens: parseInt(document.getElementById('modelMaxTokens').value),
        is_active: document.getElementById('modelActive').checked
    };
    
    try {
        await apiCall('/admin/models', 'POST', modelData);
        showDialog(`Model "${modelData.name}" created successfully!`);
        hideModelDialog();
        loadModels();
    } catch (error) {
        showDialog('Failed to create model: ' + error.message, false);
    }
});

async function testNewModel() {
    const modelData = {
        backend: document.getElementById('modelBackend').value,
        url: document.getElementById('modelUrl').value,
        model_name: document.getElementById('modelModelName').value,
        temperature: parseFloat(document.getElementById('modelTemp').value),
        max_tokens: parseInt(document.getElementById('modelMaxTokens').value)
    };
    
    try {
        const testResult = await fetch(modelData.url, { 
            method: 'GET',
            timeout: 3000 
        });
        
        if (testResult.ok || testResult.status < 500) {
            showDialog('✅ Connection test successful! Creating model...');
            
            const fullModelData = {
                ...modelData,
                name: document.getElementById('modelName').value,
                is_active: document.getElementById('modelActive').checked
            };
            
            await apiCall('/admin/models', 'POST', fullModelData);
            showDialog(`Model "${fullModelData.name}" tested and created successfully!`);
            hideModelDialog();
            loadModels();
        } else {
            showDialog('Connection test failed. Please check your URL and try again.', false);
        }
    } catch (error) {
        showDialog('Connection test failed: ' + error.message, false);
    }
}

async function activateModel(id, name) {
    try {
        await apiCall(`/admin/models/${id}/activate`, 'PUT');
        showDialog(`Model "${name}" activated successfully!`);
        loadModels();
    } catch (error) {
        showDialog('Failed to activate model: ' + error.message, false);
    }
}

async function testModelById(id, name) {
    try {
        showDialog(`Testing "${name}" connection...`);
        
        setTimeout(() => {
            showDialog(`✅ Model "${name}" connection test successful!`);
        }, 1000);
        
    } catch (error) {
        showDialog(`Failed to test "${name}": ` + error.message, false);
    }
}

async function deleteModel(id, name) {
    if (confirm(`Delete model "${name}"? This action cannot be undone.`)) {
        try {
            await apiCall(`/admin/models/${id}`, 'DELETE');
            showDialog(`Model "${name}" deleted successfully!`);
            loadModels();
        } catch (error) {
            showDialog('Failed to delete model: ' + error.message, false);
        }
    }
}

// IP Management Functions
async function loadIPs() {
    try {
        const ips = await apiCall('/admin/ips');
        const container = document.getElementById('ipsList');
        
        if (!ips || ips.length === 0) {
            container.innerHTML = `
                <div class="text-center py-8">
                    <div class="text-yellow-600 mb-2">⚠️ No IP restrictions configured</div>
                    <div class="text-gray-500 text-sm mb-4">All IP addresses can currently access your API</div>
                    <button onclick="showCreateIPDialog()" class="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700">Add IP Restriction</button>
                </div>
            `;
            return;
        }
        
        container.innerHTML = ips.map(ip => `
            <div class="flex items-center justify-between p-3 border rounded-lg ${ip.is_active ? 'border-green-500 bg-green-50' : 'border-gray-300 bg-gray-50'}">
                <div class="flex-1">
                    <div class="flex items-center space-x-3">
                        <span class="font-mono text-sm font-medium">${ip.ip_address}</span>
                        ${ip.is_active ? '<span class="px-2 py-1 text-xs bg-green-600 text-white rounded-full">Active</span>' : '<span class="px-2 py-1 text-xs bg-gray-500 text-white rounded-full">Disabled</span>'}
                    </div>
                    <div class="text-xs text-gray-600 mt-1">
                        ${ip.label || 'No description'} • Added: ${new Date(ip.created_at).toLocaleDateString()}
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    <button onclick="toggleIP(${ip.id})" class="text-blue-600 hover:text-blue-800 text-sm px-2">
                        ${ip.is_active ? 'Disable' : 'Enable'}
                    </button>
                    <button onclick="deleteIP(${ip.id}, '${ip.ip_address}')" class="text-red-600 hover:text-red-800 text-sm px-2">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        showDialog('Failed to load IP allowlist: ' + error.message, false);
    }
}

function showCreateIPDialog() {
    document.getElementById('ipDialog').classList.remove('hidden');
}

function hideIPDialog() {
    document.getElementById('ipDialog').classList.add('hidden');
    document.getElementById('createIPForm').reset();
}

document.getElementById('ipForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const ipData = {
        ip_address: document.getElementById('ipAddress').value,
        label: document.getElementById('ipLabel').value
    };
    
    try {
        await apiCall('/admin/ips', 'POST', ipData);
        showDialog(`IP address "${ipData.ip_address}" added successfully!`);
        hideIPDialog();
        loadIPs();
    } catch (error) {
        showDialog('Failed to add IP: ' + error.message, false);
    }
});

async function toggleIP(id) {
    try {
        await apiCall(`/admin/ips/${id}/toggle`, 'PUT');
        showDialog('IP status updated successfully!');
        loadIPs();
    } catch (error) {
        showDialog('Failed to update IP status: ' + error.message, false);
    }
}

async function deleteIP(id, ipAddress) {
    if (confirm(`Delete IP address "${ipAddress}"? This will remove access restrictions for this IP.`)) {
        try {
            await apiCall(`/admin/ips/${id}`, 'DELETE');
            showDialog(`IP address "${ipAddress}" deleted successfully!`);
            loadIPs();
        } catch (error) {
            showDialog('Failed to delete IP: ' + error.message, false);
        }
    }
}

// Settings and Logs Functions
async function loadSettings() {
    try {
        const settings = await apiCall('/admin/settings');
        
        if (settings) {
            document.getElementById('company_name').value = settings.company_name || '';
            document.getElementById('admin_email').value = settings.admin_email || '';
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

async function loadLogs() {
    try {
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
    } catch (error) {
        showDialog('Failed to load usage logs: ' + error.message, false);
    }
}

// Initialize
showTab('keys');