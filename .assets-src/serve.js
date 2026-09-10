const http = require("http");
const fs = require("fs");
const path = require("path");
http.createServer((req, res) => {
  const f = path.join(__dirname, req.url.replace(/^\/+/, "") || "og.html");
  try {
    res.setHeader("Content-Type", "text/html");
    res.end(fs.readFileSync(f));
  } catch {
    res.statusCode = 404;
    res.end("not found");
  }
}).listen(8090, "127.0.0.1", () => console.log("ready"));
