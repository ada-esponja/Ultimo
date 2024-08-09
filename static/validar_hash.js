document.addEventListener('DOMContentLoaded', function() {
    const tableRows = document.querySelectorAll('#fileTable tbody tr');

    tableRows.forEach(row => {
        const fileContent = row.querySelector('input[name="fileContent"]').value;
        const originalHash = row.getAttribute('data-original-hash');
        const encryptionAlgorithm = row.getAttribute('data-encryption-algorithm');

        // Calculate the hash of the current file content based on the specified algorithm
        calculateHash(fileContent, encryptionAlgorithm).then(currentHash => {
            // Compare current hash with original hash
            if (currentHash !== originalHash) {
                row.classList.add('hash-mismatch');
            }
        });
    });
});

function calculateHash(content, algorithm) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);

    let hashAlgorithm;
    switch (algorithm) {
        case 'SHA128':
            hashAlgorithm = 'SHA-256'; // SHA-128 is not directly supported, use SHA-256 and truncate
            break;
        case 'SHA256':
            hashAlgorithm = 'SHA-256';
            break;
        case 'SHA512':
            hashAlgorithm = 'SHA-512';
            break;
        default:
            console.error('Unsupported algorithm:', algorithm);
            return Promise.resolve('');
    }

    return crypto.subtle.digest(hashAlgorithm, data).then(hashBuffer => {
        // Convert ArrayBuffer to hex string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        let hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // For SHA128, truncate the result to 32 characters
        if (algorithm === 'SHA128') {
            hashHex = hashHex.substring(0, 32);
        }

        return hashHex;
    });
}
