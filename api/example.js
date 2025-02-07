const options = {
    method: 'POST',
    // View all available options for tls : https://bogdanfinn.gitbook.io/open-source-oasis/shared-library/payload
    body: JSON.stringify({
        disableIPV6: true,
        tlsClientIdentifier: 'chrome_133',
        withRandomTLSExtensionOrder: true,
        timeoutSeconds: 10,
        requestUrl: 'https://tls.peet.ws/api/all',
        requestMethod: 'GET',
    }),
    headers: {
        'Content-Type': 'application/json',
        'x-api-key': 'socket'
    }
}

fetch('http://127.0.0.1:2389/api/forward', options)
    .then(res => res.json())
    .then(data => {
        console.log(data)
    })
    .catch(err => {
        console.error(err)
    })