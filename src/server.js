require('dotenv').config(); // Reads local .env when present; CI and Docker can provide environment values directly.
const app = require('./app');
const port = Number(process.env.PORT || 3000);
app.listen(port, '0.0.0.0', () => console.log(`SecureNotes listening on port ${port}`));
