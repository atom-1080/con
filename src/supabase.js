// Compatibility shim.
//
// The application client lives in src/lib/supabaseClient.js, which resolves its
// credentials from src/config.js: window.__LSP_CONFIG__ (written at container
// start by server.mjs from SUPABASE_URL / SUPABASE_ANON_KEY) or the build-time
// values injected by vite.config.js. That is the only configuration contract the
// deployment platform needs.
//
// This file previously created a second client from import.meta.env.VITE_*
// and threw at import time when those names were absent, which contradicted the
// documented setup. It now re-exports the shared client so both import paths are
// identical and no extra environment variables are required.
export { supabase, isSupabaseConfigured } from './lib/supabaseClient.js';
