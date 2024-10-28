// Função para obter o valor de um cookie específico
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Obter o CSRF token
const csrfToken = getCookie('csrf_token');

// Adiciona o CSRF token a cada solicitação de fetch
document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const user = document.getElementById('user').value.trim();
    const passwd = document.getElementById('passwd').value.trim();
    const mfaDiv = document.getElementById('mfaDiv');
    const mfa = document.getElementById('otp_secret').value.trim();
    const responseMessage = document.getElementById('responseMessage');
    responseMessage.textContent = '';

    try {
        const response = await fetch('/api/v2/check_2fa', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken // Inclui o CSRF token aqui
            },
            body: JSON.stringify({ user, passwd })
        });

        const result = await response.json();
        if (response.ok) {
            if (result.requires_2fa) {
                mfaDiv.style.display = 'block';
                if (!mfa) {
                    responseMessage.textContent = 'Please enter your MFA code.';
                    responseMessage.style.color = 'red';
                    return;
                }
            }

            const loginResponse = await fetch('/api/v2/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ user, passwd, mfa })
            });

            const loginResult = await loginResponse.json();
            if (loginResponse.ok) {
                window.location.href = '/dashboard';
            } else {
                responseMessage.textContent = loginResult.error || 'Login failed. Please check your credentials and try again.';
                responseMessage.style.color = 'red';
            }
        } else {
            responseMessage.textContent = result.error || 'Error during 2FA check. Please try again.';
            responseMessage.style.color = 'red';
        }
    } catch (error) {
        console.error('Error communicating with the server:', error);
        responseMessage.textContent = 'Error communicating with the server!';
        responseMessage.style.color = 'red';
    }
});

// Mesma lógica para enviar o CSRF token nas demais requisições
// Configurações e upload de imagem também deverão conter o `X-CSRFToken` nos cabeçalhos

document.getElementById('settingsForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    
    const new_password = document.getElementById('new_password').value.trim();
    const otp_secret = document.getElementById('otp_secret').value.trim();
    const confirm_totp = document.getElementById('confirm_totp').checked;
    const serialized_data = document.getElementById('serialized_data').value.trim();
    const responseMessage = document.getElementById('responseMessage');
    responseMessage.textContent = '';

    if (otp_secret && !confirm_totp) {
        responseMessage.textContent = 'Please confirm that you have copied the TOTP code.';
        responseMessage.style.color = 'red';
        return;
    }

    try {
        const response = await fetch('/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': csrfToken
            },
            body: new URLSearchParams({
                new_password,
                otp_secret,
                serialized_data
            })
        });

        const result = await response.json();
        responseMessage.textContent = result.message || result.error;
        responseMessage.style.color = response.ok ? 'green' : 'red';
    } catch (error) {
        console.error('Error communicating with the server:', error);
        responseMessage.textContent = 'An unexpected error occurred. Please try again later.';
        responseMessage.style.color = 'red';
    }
});

// Profile image upload
document.getElementById('profileForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    
    const formData = new FormData();
    const fileInput = document.getElementById('profile_image');
    const file = fileInput.files[0];
    const responseMessage = document.getElementById('profileResponseMessage');

    if (!file) {
        responseMessage.textContent = 'Please select a file to upload.';
        responseMessage.style.color = 'red';
        return;
    }

    formData.append('image', file);

    try {
        const response = await fetch('/settings/profile', {
            method: 'POST',
            headers: { 'X-CSRFToken': csrfToken }, // Inclui o CSRF token aqui
            body: formData
        });

        const result = await response.json();
        responseMessage.textContent = result.message || result.error;
        responseMessage.style.color = response.ok ? 'green' : 'red';
    } catch (error) {
        console.error('Error uploading profile image:', error);
        responseMessage.textContent = 'Failed to upload image.';
        responseMessage.style.color = 'red';
    }
});
