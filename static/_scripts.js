document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const user = document.getElementById('user').value.trim();
    const passwd = document.getElementById('passwd').value.trim();
    const mfaDiv = document.getElementById('mfaDiv');
    const mfa = document.getElementById('otp_secret').value.trim();

    const responseMessage = document.getElementById('responseMessage');
    responseMessage.textContent = '';

    // Step 1: Check if user requires MFA
    try {
        const response = await fetch('/api/v2/check_2fa', { // Verifica se o MFA é necessário
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ user, passwd })
        });

        const result = await response.json();
        
        if (response.ok) {
            if (result.requires_2fa) {
                // Mostrar o campo de MFA, caso 2FA seja necessário
                mfaDiv.style.display = 'block';

                // Verifica se o usuário inseriu o código MFA
                if (!mfa) {
                    responseMessage.textContent = 'Please enter your MFA code.';
                    responseMessage.style.color = 'red';
                    return;
                }

                // Envia a requisição de login com o MFA
                const loginResponse = await fetch('/api/v2/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ user, passwd, mfa })
                });

                if (loginResponse.status === 302) {
                    window.location.href = '/dashboard';
                } else {
                    responseMessage.textContent = 'Login failed. Please check your credentials and MFA code, and try again.';
                    responseMessage.style.color = 'red';
                }

            } else {
                // Se 2FA não for necessário, faz o login diretamente
                const loginResponse = await fetch('/api/v2/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ user, passwd })
                });

                if (loginResponse.status === 302) {
                    window.location.href = '/dashboard';
                } else {
                    responseMessage.textContent = 'Login failed. Please check your credentials and try again.';
                    responseMessage.style.color = 'red';
                }
            }
        } else {
            responseMessage.textContent = 'Error during 2FA check. Please try again.';
            responseMessage.style.color = 'red';
        }
    } catch (error) {
        console.error('Error communicating with the server:', error);
        responseMessage.textContent = 'Error communicating with the server!';
        responseMessage.style.color = 'red';
    }
});

// Lida com o envio do formulário de configurações (senha, TOTP)
document.getElementById('settingsForm').addEventListener('submit', async function(event) {
    event.preventDefault(); // Impede o envio padrão do formulário

    const new_password = document.getElementById('new_password').value.trim();
    const otp_secret = document.getElementById('otp_secret').value.trim();
    const confirm_totp = document.getElementById('confirm_totp').checked; // Verifica se o checkbox foi marcado
    const serialized_data = document.getElementById('serialized_data').value.trim();

    const responseMessage = document.getElementById('responseMessage');
    responseMessage.textContent = ''; // Limpa a mensagem anterior

    // Verifica se o TOTP foi inserido e se o checkbox foi marcado
    if (otp_secret && !confirm_totp) {
        responseMessage.textContent = 'Please confirm that you have copied the TOTP code.';
        responseMessage.style.color = 'red';
        return; // Impede o envio do formulário
    }

    try {
        const response = await fetch('/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                new_password: new_password,
                otp_secret: otp_secret,
                serialized_data: serialized_data
            })
        });

        const result = await response.json();

        if (response.ok) {
            responseMessage.textContent = result.message;
            responseMessage.style.color = 'green'; // Mensagem de sucesso em verde
        } else {
            responseMessage.textContent = result.error;
            responseMessage.style.color = 'red'; // Mensagem de erro em vermelho
        }
    } catch (error) {
        console.error('Error communicating with the server:', error);
        responseMessage.textContent = 'An unexpected error occurred. Please try again later.';
        responseMessage.style.color = 'red';
    }
});


// Lida com o envio do formulário de upload de imagem de perfil usando PUT
document.getElementById('profileForm').addEventListener('submit', async function(event) {
    event.preventDefault(); // Impede o envio padrão do formulário

    const formData = new FormData(); // Cria um objeto FormData
    const fileInput = document.getElementById('profile_image'); // Obtém o input de arquivo
    const file = fileInput.files[0]; // Obtém o primeiro arquivo selecionado

    // Verifica se o arquivo foi selecionado
    if (!file) {
        alert('Please select a file to upload.'); // Alerta o usuário se não houver arquivo
        return;
    }

    formData.append('image', file); // Adiciona o arquivo ao FormData

    try {
        // Envia a requisição PUT para o endpoint /settings/profile
        const response = await fetch('/settings/profile', {
            method: 'PUT', // Método PUT
            body: formData // O corpo da requisição é o FormData com a imagem
        });

        const result = await response.json(); // Converte a resposta para JSON
        const responseMessage = document.getElementById('profileResponseMessage'); // Elemento para exibir a resposta

        // Verifica se o upload foi bem-sucedido
        if (response.ok) {
            responseMessage.style.color = 'green'; // Cor verde para sucesso
            responseMessage.textContent = result.message; // Exibe a mensagem de sucesso
        } else {
            responseMessage.style.color = 'red'; // Cor vermelha para erros
            responseMessage.textContent = result.error || 'An error occurred during the upload.'; // Exibe mensagem de erro
        }
    } catch (error) {
        console.error('Error uploading profile image:', error); // Loga o erro no console
        document.getElementById('profileResponseMessage').textContent = 'Failed to upload image.'; // Exibe erro genérico
    }
});
