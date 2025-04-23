// login.js - Place this in src/main/resources/static/js/login.js

document.addEventListener('DOMContentLoaded', function() {
    // Check if WebAuthn is available
    if (window.PublicKeyCredential) {
        console.log('WebAuthn is supported in this browser');
        
        // Add event listener to the button
        const passkeyButton = document.getElementById('passkey-button');
        if (passkeyButton) {
            passkeyButton.addEventListener('click', loginWithPasskey);
        }
    } else {
        console.error('WebAuthn is not supported in this browser');
        const statusElement = document.getElementById('passkey-status');
        if (statusElement) {
            statusElement.textContent = 'Passkeys are not supported in this browser';
        }
        
        const buttonElement = document.getElementById('passkey-button');
        if (buttonElement) {
            buttonElement.disabled = true;
        }
    }
});

async function loginWithPasskey() {
    try {
        const statusDiv = document.getElementById('passkey-status');
        statusDiv.textContent = 'Authenticating...';
        
        // Check if authenticateWithPasskey function exists
        if (typeof authenticateWithPasskey !== 'function') {
            throw new Error('WebAuthn functions not loaded properly');
        }
        
        // Pass null explicitly to match the function signature
        const result = await authenticateWithPasskey(null);
        
        if (result.success) {
            statusDiv.textContent = result.message;
            window.location.href = result.redirectUrl || '/dashboard';
        } else {
            statusDiv.textContent = 'Error: ' + result.message;
        }
    } catch (error) {
        console.error('Passkey login error:', error);
        document.getElementById('passkey-status').textContent = 'Error: ' + error.message;
    }
}