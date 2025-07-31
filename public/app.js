// Secure Digital Locker - Client Side Application
class SecureDigitalLocker {
    constructor() {
        this.currentUser = null;
        this.documents = [];
        this.API_BASE_URL = window.location.hostname === 'localhost' ? 'http://localhost:3000' : '';
        this.isDemo = window.location.hostname !== 'localhost';
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkAuthState();
        
        // Initialize demo data if in GitHub Pages
        if (this.isDemo) {
            this.initDemoData();
        }
    }

    initDemoData() {
        // Demo user data
        this.demoUser = {
            email: 'demo@company.com',
            role: 'Employee',
            employeeId: 'EMP001'
        };

        // Demo documents
        this.documents = [
            {
                id: '1',
                filename: 'offer-letter-2024.pdf',
                documentType: 'offer_letter',
                employeeId: 'EMP001',
                size: '245KB',
                uploadedAt: new Date('2024-01-15'),
                description: 'Job offer letter for Software Engineer position'
            },
            {
                id: '2',
                filename: 'employee-id-card.jpg',
                documentType: 'id_proof',
                employeeId: 'EMP001',
                size: '156KB',
                uploadedAt: new Date('2024-01-20'),
                description: 'Company issued employee identification card'
            },
            {
                id: '3',
                filename: 'salary-slip-march-2024.pdf',
                documentType: 'salary_slip',
                employeeId: 'EMP001',
                size: '89KB',
                uploadedAt: new Date('2024-03-31'),
                description: 'Monthly salary slip for March 2024'
            },
            {
                id: '4',
                filename: 'aws-certification.pdf',
                documentType: 'certification',
                employeeId: 'EMP001',
                size: '2.1MB',
                uploadedAt: new Date('2024-02-10'),
                description: 'AWS Solutions Architect Associate Certification'
            }
        ];
    }

    bindEvents() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
        }

        // Upload modal
        const uploadBtn = document.getElementById('uploadBtn');
        const uploadModal = document.getElementById('uploadModal');
        const closeUploadModal = document.getElementById('closeUploadModal');
        const cancelUpload = document.getElementById('cancelUpload');
        const uploadForm = document.getElementById('uploadForm');

        if (uploadBtn) {
            uploadBtn.addEventListener('click', () => this.showUploadModal());
        }

        if (closeUploadModal) {
            closeUploadModal.addEventListener('click', () => this.hideUploadModal());
        }

        if (cancelUpload) {
            cancelUpload.addEventListener('click', () => this.hideUploadModal());
        }

        if (uploadForm) {
            uploadForm.addEventListener('submit', (e) => this.handleUpload(e));
        }

        // Refresh button
        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadDocuments());
        }

        // Document type filter
        const documentTypeFilter = document.getElementById('documentTypeFilter');
        if (documentTypeFilter) {
            documentTypeFilter.addEventListener('change', () => this.filterDocuments());
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const loginBtn = document.getElementById('loginBtn');
        const loginError = document.getElementById('loginError');

        this.showLoading(loginBtn, 'Signing in...');
        
        try {
            if (this.isDemo) {
                // Demo authentication
                if (email && password) {
                    this.currentUser = this.demoUser;
                    this.showDashboard();
                    this.showToast('Login successful! (Demo Mode)', 'success');
                } else {
                    throw new Error('Please enter email and password');
                }
            } else {
                // Real authentication
                const response = await fetch(`${this.API_BASE_URL}/api/auth/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (response.ok) {
                    this.currentUser = data.user;
                    localStorage.setItem('token', data.token);
                    this.showDashboard();
                    this.showToast('Login successful!', 'success');
                } else {
                    throw new Error(data.message || 'Login failed');
                }
            }
        } catch (error) {
            this.showError(loginError, error.message);
        } finally {
            this.hideLoading(loginBtn, '<i class="fas fa-sign-in-alt mr-2"></i>Sign In');
        }
    }

    handleLogout() {
        this.currentUser = null;
        localStorage.removeItem('token');
        this.showLoginScreen();
        this.showToast('Logged out successfully', 'info');
    }

    checkAuthState() {
        const token = localStorage.getItem('token');
        if (token && !this.isDemo) {
            // Verify token with backend
            this.verifyToken(token);
        } else if (this.isDemo) {
            // Show login screen for demo
            this.showLoginScreen();
        } else {
            this.showLoginScreen();
        }
    }

    async verifyToken(token) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/api/auth/verify`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.currentUser = data.user;
                this.showDashboard();
            } else {
                localStorage.removeItem('token');
                this.showLoginScreen();
            }
        } catch (error) {
            localStorage.removeItem('token');
            this.showLoginScreen();
        }
    }

    showLoginScreen() {
        document.getElementById('loginScreen').classList.remove('hidden');
        document.getElementById('dashboard').classList.add('hidden');
        document.getElementById('navbar').classList.add('hidden');
    }

    showDashboard() {
        document.getElementById('loginScreen').classList.add('hidden');
        document.getElementById('dashboard').classList.remove('hidden');
        document.getElementById('navbar').classList.remove('hidden');
        
        // Update user info in navbar
        document.getElementById('userEmail').textContent = this.currentUser.email;
        document.getElementById('userRole').textContent = this.currentUser.role;
        
        this.loadDocuments();
        this.updateStatistics();
    }

    async loadDocuments() {
        try {
            if (this.isDemo) {
                // Use demo data
                this.renderDocuments(this.documents);
            } else {
                const token = localStorage.getItem('token');
                const response = await fetch(`${this.API_BASE_URL}/api/documents`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    this.documents = data.documents;
                    this.renderDocuments(this.documents);
                } else {
                    throw new Error('Failed to load documents');
                }
            }
        } catch (error) {
            this.showToast('Error loading documents: ' + error.message, 'error');
        }
    }

    renderDocuments(documents) {
        const tbody = document.getElementById('documentsTableBody');
        const emptyState = document.getElementById('emptyState');
        
        if (documents.length === 0) {
            tbody.innerHTML = '';
            emptyState.classList.remove('hidden');
            return;
        }

        emptyState.classList.add('hidden');
        
        tbody.innerHTML = documents.map(doc => `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                        <div class="flex-shrink-0 h-10 w-10">
                            <div class="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                                <i class="fas fa-file-alt text-blue-600"></i>
                            </div>
                        </div>
                        <div class="ml-4">
                            <div class="text-sm font-medium text-gray-900">${doc.filename}</div>
                            <div class="text-sm text-gray-500">${doc.description || 'No description'}</div>
                        </div>
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${this.getTypeColor(doc.documentType)}">
                        ${this.formatDocumentType(doc.documentType)}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${doc.size}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${this.formatDate(doc.uploadedAt)}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <div class="flex space-x-2">
                        <button onclick="app.viewDocument('${doc.id}')" class="text-blue-600 hover:text-blue-900">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button onclick="app.downloadDocument('${doc.id}')" class="text-green-600 hover:text-green-900">
                            <i class="fas fa-download"></i>
                        </button>
                        <button onclick="app.deleteDocument('${doc.id}')" class="text-red-600 hover:text-red-900">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    filterDocuments() {
        const filterValue = document.getElementById('documentTypeFilter').value;
        const filteredDocs = filterValue 
            ? this.documents.filter(doc => doc.documentType === filterValue)
            : this.documents;
        
        this.renderDocuments(filteredDocs);
    }

    updateStatistics() {
        const totalDocs = this.documents.length;
        const recentUploads = this.documents.filter(doc => {
            const uploadDate = new Date(doc.uploadedAt);
            const oneWeekAgo = new Date();
            oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
            return uploadDate > oneWeekAgo;
        }).length;

        const totalViews = this.documents.reduce((sum, doc) => sum + (doc.views || Math.floor(Math.random() * 20) + 1), 0);
        const storageUsed = this.documents.reduce((sum, doc) => {
            const sizeMatch = doc.size.match(/(\d+(?:\.\d+)?)(KB|MB)/);
            if (sizeMatch) {
                const value = parseFloat(sizeMatch[1]);
                const unit = sizeMatch[2];
                return sum + (unit === 'MB' ? value : value / 1024);
            }
            return sum;
        }, 0);

        document.getElementById('totalDocs').textContent = totalDocs;
        document.getElementById('recentUploads').textContent = recentUploads;
        document.getElementById('totalViews').textContent = totalViews;
        document.getElementById('storageUsed').textContent = `${storageUsed.toFixed(1)} MB`;
    }

    showUploadModal() {
        document.getElementById('uploadModal').classList.remove('hidden');
    }

    hideUploadModal() {
        document.getElementById('uploadModal').classList.add('hidden');
        document.getElementById('uploadForm').reset();
    }

    async handleUpload(e) {
        e.preventDefault();
        
        const formData = new FormData();
        const file = document.getElementById('uploadFile').files[0];
        const documentType = document.getElementById('uploadDocumentType').value;
        const employeeId = document.getElementById('uploadEmployeeId').value;
        const description = document.getElementById('uploadDescription').value;
        
        if (!file || !documentType || !employeeId) {
            this.showToast('Please fill in all required fields', 'error');
            return;
        }

        if (this.isDemo) {
            // Demo upload
            const newDoc = {
                id: Date.now().toString(),
                filename: file.name,
                documentType: documentType,
                employeeId: employeeId,
                size: this.formatFileSize(file.size),
                uploadedAt: new Date(),
                description: description
            };
            
            this.documents.unshift(newDoc);
            this.hideUploadModal();
            this.loadDocuments();
            this.updateStatistics();
            this.showToast('Document uploaded successfully! (Demo Mode)', 'success');
            return;
        }

        formData.append('file', file);
        formData.append('documentType', documentType);
        formData.append('employeeId', employeeId);
        formData.append('description', description);

        const submitBtn = document.getElementById('submitUpload');
        this.showLoading(submitBtn, 'Uploading...');

        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`${this.API_BASE_URL}/api/documents/upload`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });

            const data = await response.json();

            if (response.ok) {
                this.hideUploadModal();
                this.loadDocuments();
                this.updateStatistics();
                this.showToast('Document uploaded successfully!', 'success');
            } else {
                throw new Error(data.message || 'Upload failed');
            }
        } catch (error) {
            this.showToast('Upload error: ' + error.message, 'error');
        } finally {
            this.hideLoading(submitBtn, '<i class="fas fa-upload mr-2"></i>Upload');
        }
    }

    viewDocument(docId) {
        if (this.isDemo) {
            this.showToast('Document viewing is available in the full version', 'info');
            return;
        }
        
        const token = localStorage.getItem('token');
        window.open(`${this.API_BASE_URL}/api/documents/${docId}/view`, '_blank');
    }

    downloadDocument(docId) {
        if (this.isDemo) {
            this.showToast('Document download is available in the full version', 'info');
            return;
        }
        
        const token = localStorage.getItem('token');
        window.open(`${this.API_BASE_URL}/api/documents/${docId}/download`, '_blank');
    }

    async deleteDocument(docId) {
        if (!confirm('Are you sure you want to delete this document?')) {
            return;
        }

        if (this.isDemo) {
            this.documents = this.documents.filter(doc => doc.id !== docId);
            this.loadDocuments();
            this.updateStatistics();
            this.showToast('Document deleted successfully! (Demo Mode)', 'success');
            return;
        }

        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`${this.API_BASE_URL}/api/documents/${docId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                this.loadDocuments();
                this.updateStatistics();
                this.showToast('Document deleted successfully!', 'success');
            } else {
                const data = await response.json();
                throw new Error(data.message || 'Delete failed');
            }
        } catch (error) {
            this.showToast('Delete error: ' + error.message, 'error');
        }
    }

    // Utility methods
    getTypeColor(type) {
        const colors = {
            'offer_letter': 'bg-blue-100 text-blue-800',
            'id_proof': 'bg-green-100 text-green-800',
            'salary_slip': 'bg-yellow-100 text-yellow-800',
            'certification': 'bg-purple-100 text-purple-800',
            'contract': 'bg-red-100 text-red-800',
            'performance_review': 'bg-indigo-100 text-indigo-800',
            'other': 'bg-gray-100 text-gray-800'
        };
        return colors[type] || colors['other'];
    }

    formatDocumentType(type) {
        const types = {
            'offer_letter': 'Offer Letter',
            'id_proof': 'ID Proof',
            'salary_slip': 'Salary Slip',
            'certification': 'Certification',
            'contract': 'Contract',
            'performance_review': 'Performance Review',
            'other': 'Other'
        };
        return types[type] || 'Other';
    }

    formatDate(date) {
        return new Date(date).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    showLoading(button, text) {
        button.disabled = true;
        button.innerHTML = `<i class="fas fa-spinner fa-spin mr-2"></i>${text}`;
    }

    hideLoading(button, originalText) {
        button.disabled = false;
        button.innerHTML = originalText;
    }

    showError(errorElement, message) {
        const errorMessage = errorElement.querySelector('#loginErrorMessage');
        if (errorMessage) {
            errorMessage.textContent = message;
        }
        errorElement.classList.remove('hidden');
        
        setTimeout(() => {
            errorElement.classList.add('hidden');
        }, 5000);
    }

    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        
        const colors = {
            success: 'bg-green-500',
            error: 'bg-red-500',
            info: 'bg-blue-500',
            warning: 'bg-yellow-500'
        };

        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            info: 'fa-info-circle',
            warning: 'fa-exclamation-triangle'
        };

        toast.className = `${colors[type]} text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 transform transition-all duration-300`;
        toast.innerHTML = `
            <i class="fas ${icons[type]}"></i>
            <span>${message}</span>
        `;

        toastContainer.appendChild(toast);

        // Animate in
        setTimeout(() => {
            toast.style.transform = 'translateX(0)';
        }, 100);

        // Remove after 5 seconds
        setTimeout(() => {
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 5000);
    }
}

// Initialize the application
const app = new SecureDigitalLocker();

// Add demo info banner for GitHub Pages
if (window.location.hostname !== 'localhost') {
    document.addEventListener('DOMContentLoaded', () => {
        const banner = document.createElement('div');
        banner.className = 'bg-blue-600 text-white text-center py-2 px-4 text-sm';
        banner.innerHTML = `
            <i class="fas fa-info-circle mr-2"></i>
            This is a demo version running on GitHub Pages. 
            Login with any email/password to explore the interface.
            <a href="#" class="underline ml-2" onclick="app.showToast('Demo credentials: Any email and password will work', 'info')">Need help?</a>
        `;
        document.body.insertBefore(banner, document.body.firstChild);
    });
}