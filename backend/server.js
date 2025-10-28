const http = require('http');

const server = http.createServer((req, res) => {
  console.log("Backend got:", req.method, req.url);   // <-- log the request method and URL

  let body = [];
  req.on('data', chunk => body.push(chunk));
  req.on('end', () => {
    body = Buffer.concat(body).toString();
    const payload = JSON.stringify({
      message: "Hello from backend",
      method: req.method,
      url: req.url,
      headers: req.headers,
      body
    });
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(payload),
      'Connection': 'close'
    });
    res.end(payload);
  });
});

server.listen(8080, '127.0.0.1', () => {
  console.log('Backend listening on http://127.0.0.1:8080');
});
