/**
 * Voight-Kampff Authentication Frontend
 * Centralized authentication interface for all services
 */

class VoightKampffAuth {
    constructor() {
        this.apiBaseUrl = window.location.origin; // Current Voight-Kampff URL
        this.initializeEventListeners();
        this.checkExistingAuth();
        this.handleUrlParams();
    }

    initializeEventListeners() {
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        const registerForm = document.getElementById('register-form');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegister();
            });
        }

        const registerLink = document.getElementById('register-link');
        if (registerLink) {
            registerLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showRegisterForm();
            });
        }

        const backToLoginLink = document.getElementById('back-to-login-link');
        if (backToLoginLink) {
            backToLoginLink.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.href = '/auth/login' + this.getRedirectParams();
            });
        }

        // Password validation for registration
        const regPassword = document.getElementById('reg-password');
        if (regPassword) {
            regPassword.addEventListener('input', (e) => {
                this.validatePasswordRules(e.target.value);
            });
        }
    }

    handleUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const redirect = urlParams.get('redirect');
        const serviceName = urlParams.get('service_name');
        
        // Show service info if redirecting from a specific service
        if (redirect && serviceName) {
            this.showServiceInfo(serviceName, redirect);
        }
    }

    getRedirectParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const redirect = urlParams.get('redirect');
        const serviceName = urlParams.get('service_name');
        
        if (redirect) {
            let params = `?redirect=${encodeURIComponent(redirect)}`;
            if (serviceName) {
                params += `&service_name=${encodeURIComponent(serviceName)}`;
            }
            return params;
        }
        return '';
    }

    showServiceInfo(serviceName, redirectUrl) {
        const container = document.querySelector('.auth-form');
        if (!container) return;

        const serviceInfo = document.createElement('div');
        serviceInfo.className = 'service-info';
        serviceInfo.innerHTML = `
            <strong>🔐 Authentification requise</strong><br>
            Connectez-vous pour accéder à <strong>${serviceName}</strong>
        `;
        
        container.insertBefore(serviceInfo, container.firstChild);
    }

    async checkExistingAuth() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/verify`, {
                credentials: 'include'
            });
            
            if (response.ok) {
                // Already authenticated, handle redirect
                const urlParams = new URLSearchParams(window.location.search);
                const redirect = urlParams.get('redirect');
                
                if (redirect) {
                    window.location.href = redirect;
                } else {
                    // Redirect to dashboard
                    window.location.href = '/auth/dashboard';
                }
            }
        } catch (error) {
            console.log('No existing authentication');
        }
    }

    async handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const loginBtn = document.getElementById('login-btn');
        const errorDiv = document.getElementById('error-message');
        const successDiv = document.getElementById('success-message');

        // Reset messages
        this.hideMessage(errorDiv);
        this.hideMessage(successDiv);

        // Show loading state
        this.setButtonLoading(loginBtn, true);

        try {
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            
            // Add redirect parameter if present
            const urlParams = new URLSearchParams(window.location.search);
            const redirect = urlParams.get('redirect');
            if (redirect) {
                formData.append('redirect', redirect);
            }

            const response = await fetch(`${this.apiBaseUrl}/auth/login`, {
                method: 'POST',
                body: formData,
                credentials: 'include'
            });

            const data = await response.json();

            if (response.ok && data.success) {
                this.showMessage(successDiv, 'Connexion réussie ! Redirection...');
                
                // Redirect to specified URL or dashboard
                setTimeout(() => {
                    if (data.next_url) {
                        window.location.href = data.next_url;
                    } else if (redirect) {
                        window.location.href = redirect;
                    } else {
                        window.location.href = '/auth/dashboard';
                    }
                }, 1000);
            } else {
                this.showMessage(errorDiv, data.error || 'Erreur de connexion');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showMessage(errorDiv, 'Erreur de réseau. Veuillez vérifier votre connexion.');
        } finally {
            this.setButtonLoading(loginBtn, false);
        }
    }

    async handleRegister() {
        const username = document.getElementById('reg-username').value;
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;
        const passwordConfirm = document.getElementById('reg-password-confirm').value;
        const registerBtn = document.getElementById('register-btn');
        const errorDiv = document.getElementById('error-message');
        const successDiv = document.getElementById('success-message');

        // Reset messages
        this.hideMessage(errorDiv);
        this.hideMessage(successDiv);

        // Validate passwords match
        if (password !== passwordConfirm) {
            this.showMessage(errorDiv, 'Les mots de passe ne correspondent pas.');
            return;
        }

        // Validate password strength
        if (!this.validatePasswordRules(password)) {
            this.showMessage(errorDiv, 'Le mot de passe ne respecte pas tous les critères.');
            return;
        }

        // Show loading state
        this.setRegisterButtonLoading(registerBtn, true);

        try {
            const formData = new FormData();
            formData.append('username', username);
            formData.append('email', email);
            formData.append('password', password);
            formData.append('password_confirm', passwordConfirm);

            const response = await fetch(`${this.apiBaseUrl}/auth/register`, {
                method: 'POST',
                body: formData,
                credentials: 'include'
            });

            const data = await response.json();

            if (response.ok && data.success) {
                this.showMessage(successDiv, data.message);
                // Disable form after successful registration
                document.getElementById('register-form').style.display = 'none';
            } else {
                this.showMessage(errorDiv, data.detail || data.error || 'Erreur lors de la création du compte.');
            }
        } catch (error) {
            console.error('Register error:', error);
            this.showMessage(errorDiv, 'Erreur de réseau. Veuillez réessayer.');
        } finally {
            this.setRegisterButtonLoading(registerBtn, false);
        }
    }

    showRegisterForm() {
        // Get current redirect parameters to preserve them
        const redirectParams = this.getRedirectParams();
        
        // Redirect to register page with parameters
        window.location.href = `/auth/register${redirectParams}`;
    }

    validatePasswordRules(password) {
        const rules = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\d/.test(password)
        };

        // Update visual indicators if elements exist
        Object.keys(rules).forEach(ruleKey => {
            const ruleElement = document.getElementById(`rule-${ruleKey}`);
            if (ruleElement) {
                const isValid = rules[ruleKey];
                
                if (isValid) {
                    ruleElement.classList.add('valid');
                    ruleElement.classList.remove('invalid');
                } else {
                    ruleElement.classList.add('invalid');
                    ruleElement.classList.remove('valid');
                }
            }
        });

        // Return overall validity
        return Object.values(rules).every(valid => valid);
    }

    setButtonLoading(button, isLoading) {
        if (!button) return;
        
        if (isLoading) {
            button.disabled = true;
            button.innerHTML = '<div class="btn-loading"><div class="loading-spinner"></div>Connexion...</div>';
        } else {
            button.disabled = false;
            button.innerHTML = 'Se connecter';
        }
    }

    setRegisterButtonLoading(button, isLoading) {
        if (!button) return;
        
        if (isLoading) {
            button.disabled = true;
            button.innerHTML = '<div class="btn-loading"><div class="loading-spinner"></div>Création...</div>';
        } else {
            button.disabled = false;
            button.innerHTML = 'Créer le compte';
        }
    }

    showMessage(element, message) {
        if (element) {
            element.textContent = message;
            element.style.display = 'block';
        }
    }

    hideMessage(element) {
        if (element) {
            element.style.display = 'none';
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new VoightKampffAuth();
});