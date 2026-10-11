# ROMORA Exact Frontend

React + JavaScript + Vite implementation of the supplied ROMORA storyboard.

## Run

```bash
npm install
npm run dev
```

Open the URL printed by Vite, usually http://localhost:5173.

## Backend integration

Start the FastAPI server from the repository root with `python -m uvicorn backend.app:app --reload`.
The UI uses `http://localhost:8000` by default; set `VITE_API_BASE_URL` before starting Vite to
use a different API origin.

Generate an identity on the Key Setup screen before sending. Public keys can be copied there for
exchange; the private keys remain in the backend process and are never returned to the frontend.
Paste the receiver's RSA public key on Send Secret and the sender's ECDSA public key on Receive
Secret. The send operation returns the actual embedded PNG for preview and download. The receive
operation displays plaintext only after the backend confirms the signature.

The backend keeps identities, authenticated ECDH session state, and image-session associations in
process memory for the demo. Sending and receiving must use the same running backend process; a
restart clears that state. This in-memory key store is not a production identity or key-management
system. Use HTTPS and an authenticated persistent key store before exposing the service publicly.

The supplied storyboard's mountain artwork is included locally under `src/assets/`.
