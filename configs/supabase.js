const { createClient } = require('@supabase/supabase-js');
const config = require('./env');

if (!config.supabase.url || !config.supabase.key) {
    throw new Error('Supabase URL dan Key belum diatur di file .env!');
}

const supabase = createClient(config.supabase.url, config.supabase.key);

module.exports = supabase;