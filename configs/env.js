require('dotenv').config();

module.exports = {
    port: process.env.PORT || 8080,
    supabase: {
        url: process.env.SUPABASE_URL,
        key: process.env.SUPABASE_KEY 
    }
};