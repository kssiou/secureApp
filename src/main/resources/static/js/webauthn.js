// webauthn.js
async function registerPasskey(username) {
    try {
      // 1. Get registration options from server
      const response = await fetch('/webauthn/register/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      
      if (!response.ok) {
        throw new Error('Failed to start registration');
      }
      
      const options = await response.json();
      
      // 2. Prepare options for WebAuthn API
      const publicKeyOptions = {
        challenge: base64ToArrayBuffer(options.challenge),
        rp: options.rp,
        user: {
          id: base64ToArrayBuffer(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName
        },
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout,
        attestation: options.attestation,
        authenticatorSelection: options.authenticatorSelection
      };
      
      // 3. Create credential with WebAuthn API
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
      });
      
      // 4. Prepare credential for server
      const credentialForServer = {
        username: username,
        credential: {
          id: credential.id,
          rawId: arrayBufferToBase64(credential.rawId),
          type: credential.type,
          clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
          attestationObject: arrayBufferToBase64(credential.response.attestationObject)
        }
      };
      
      // 5. Send credential to server
      const verifyResponse = await fetch('/webauthn/register/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentialForServer)
      });
      
      const verifyResult = await verifyResponse.json();
      
      if (!verifyResult.success) {
        throw new Error(verifyResult.error || 'Registration failed');
      }
      
      return { success: true, message: 'Passkey registered successfully!' };
    } catch (error) {
      console.error('Registration error:', error);
      return { success: false, message: error.message };
    }
  }
  
  async function authenticateWithPasskey(username = null) {
    try {
      // 1. Get authentication options from server
      const response = await fetch('/webauthn/authenticate/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      
      if (!response.ok) {
        throw new Error('Failed to start authentication');
      }
      
      const options = await response.json();
      
      // 2. Prepare options for WebAuthn API
      const publicKeyOptions = {
        challenge: base64ToArrayBuffer(options.challenge),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification
      };
      
      if (options.allowCredentials) {
        publicKeyOptions.allowCredentials = options.allowCredentials.map(cred => ({
          id: base64ToArrayBuffer(cred.id),
          type: cred.type
        }));
      }
      
      // 3. Get credential with WebAuthn API
      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions
      });
      
      // 4. Prepare credential for server
      const credentialForServer = {
        credential: {
          id: credential.id,
          rawId: arrayBufferToBase64(credential.rawId),
          type: credential.type,
          clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
          authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
          signature: arrayBufferToBase64(credential.response.signature),
          userHandle: credential.response.userHandle ? 
            arrayBufferToBase64(credential.response.userHandle) : null
        }
      };
      
      // 5. Send credential to server
      const verifyResponse = await fetch('/webauthn/authenticate/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentialForServer)
      });
      
      const verifyResult = await verifyResponse.json();
      
      if (!verifyResult.success) {
        throw new Error(verifyResult.error || 'Authentication failed');
      }
      
      return { 
        success: true, 
        message: 'Authentication successful!',
        redirectUrl: verifyResult.redirectUrl 
      };
    } catch (error) {
      console.error('Authentication error:', error);
      return { success: false, message: error.message };
    }
  }
  
  // Utility functions
  function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
  
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }